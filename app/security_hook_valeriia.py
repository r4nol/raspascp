from flask import request, session, current_app, g
import logging
import time
import uuid
from datetime import datetime

logger = logging.getLogger("security")


def register_security_hooks(app):
    """
    Register runtime security hooks (RASP-like)
    """

    @app.before_request
    def before_request_hook():
        """
        Collect request context early.
        Must NEVER block or raise.
        """
        try:
            g.request_start_time = time.time()
            g.request_id = str(uuid.uuid4())

            g.security_context = {
                "request_id": g.request_id,
                "user_id": session.get("user_id"),
                "role": session.get("role"),
                "endpoint": request.path,
                "method": request.method,
                "client_ip": request.remote_addr,
                "user_agent": request.headers.get("User-Agent"),
            }
        except Exception as e:
            logger.error(
                "Security hook error (before_request)",
                extra={"event_type": "hook_error", "error": str(e)}
            )

    @app.after_request
    def after_request_hook(response):
        """
        Analyze response + context and emit security event if needed.
        """
        try:
            ctx = getattr(g, "security_context", {})
            latency_ms = int((time.time() - g.request_start_time) * 1000)

            # Only interested in account access
            if not request.path.startswith("/api/accounts/"):
                return response

            user_id = ctx.get("user_id")
            role = ctx.get("role")

            # Not authenticated → ignore
            if not user_id:
                return response

            # Extract account_id from URL
            try:
                resource_id = int(request.path.rstrip("/").split("/")[-1])
            except ValueError:
                return response

            # Owner mismatch flag must be set in routes
            owner_mismatch = getattr(g, "owner_mismatch", None)

            # If routes did not calculate it — skip
            if owner_mismatch is None:
                return response

            decision = "block" if response.status_code == 403 else "allow"
            event_type = "idor_block" if decision == "block" else "idor_attempt"

            security_event = {
                "event_type": event_type,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "request_id": ctx.get("request_id"),
                "user_id": user_id,
                "role": role,
                "resource_type": "account",
                "resource_id": resource_id,
                "decision": decision,
                "reason": "owner_mismatch" if owner_mismatch else "owner_match",
                "app_mode": current_app.config.get("APP_MODE", "vuln"),
                "client_ip": ctx.get("client_ip"),
                "user_agent": ctx.get("user_agent"),
                "endpoint": ctx.get("endpoint"),
                "status_code": response.status_code,
                "latency_ms": latency_ms
            }

            logger.info("Security event", extra=security_event)

        except Exception as e:
            logger.error(
                "Security hook error (after_request)",
                extra={"event_type": "hook_error", "error": str(e)}
            )

        return response
