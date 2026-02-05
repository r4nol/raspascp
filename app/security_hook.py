import os
import time
import uuid
import traceback
from datetime import datetime

from flask import request, session, g

from logging_conf import setup_security_logger, log_security_event


try:
    from ml.model_infer import risk_engine
    from ml.features import prepare_features
    _ML_AVAILABLE = True
except Exception:
    risk_engine = None
    prepare_features = None
    _ML_AVAILABLE = False


def check_access_with_ml(user_id, owner_id, context_overrides=None):
    """
    Simple ML gate to decide if access should be allowed.

    Returns:
        (allowed: bool, ml_result: dict)
    """
    context = {
        "is_owner_mismatch": int(user_id != owner_id),
        "request_rate_10s": 5,
        "resource_id_delta": 1,
        "has_suspicious_keyword": 0,
        "domain_age_days": 365,
    }
    if context_overrides:
        context.update(context_overrides)

    if not _ML_AVAILABLE or not risk_engine or not prepare_features:
        ml_result = {"risk_score": "low", "confidence": 0.0, "top_feature": "none"}
        return True, ml_result

    vector = prepare_features(context)
    ml_result = risk_engine.predict_risk(vector)

    if ml_result.get("risk_score") == "high":
        return False, ml_result
    return True, ml_result


class SecurityContext:
    """Context for a single HTTP request."""

    def __init__(self):
        self.request_id = str(uuid.uuid4())
        self.timestamp = datetime.utcnow().isoformat() + "Z"
        self.user_id = session.get("user_id")
        self.role = session.get("role", "anonymous")
        self.endpoint = request.path
        self.method = request.method
        self.client_ip = request.remote_addr
        self.user_agent = request.headers.get("User-Agent", "")

        self.is_suspicious = False
        self.violation_type = None
        self.decision = "allow"
        self.reason = None
        self.risk_score = "low"
        self.confidence = 0.0
        self.top_feature = "none"


class RulesEngine:
    """
    Security rules engine. R1: IDOR detection.
    """

    def __init__(self, get_account_func):
        self.get_account = get_account_func

    def check_idor_attempt(self, context, resource_id):
        if not context.user_id:
            return {"is_violation": False, "reason": "not_authenticated"}

        if context.role == "admin":
            return {"is_violation": False, "reason": "admin_allowed"}

        try:
            account = self.get_account(resource_id) if self.get_account else None
            if not account:
                return {"is_violation": False, "reason": "resource_not_found"}

            owner_id = account.get("owner_user_id")
            if owner_id != context.user_id:
                return {
                    "is_violation": True,
                    "reason": "owner_mismatch",
                    "resource_owner": owner_id,
                }

            return {"is_violation": False, "reason": "owner_match"}
        except Exception as exc:
            return {"is_violation": False, "reason": f"check_error: {str(exc)}"}


class DefaultMLInference:
    """Adapter around the ml module to provide get_risk_score()."""

    def __init__(self):
        self.available = _ML_AVAILABLE and risk_engine is not None and prepare_features is not None

    def get_risk_score(self, features):
        if not self.available:
            if features.get("is_owner_mismatch"):
                return {"score": "high", "confidence": 0.8, "top_feature": "is_owner_mismatch"}
            return {"score": "low", "confidence": 0.3, "top_feature": "none"}

        vector = prepare_features(features)
        result = risk_engine.predict_risk(vector)
        return {
            "score": result.get("risk_score", "low"),
            "confidence": result.get("confidence", 0.0),
            "top_feature": result.get("top_feature", "none"),
        }


class SecurityHook:
    """Runtime Security Hook integrated via Flask hooks."""

    def __init__(self, app, ml_inference, get_account_func):
        self.app = app
        self.ml_inference = ml_inference or DefaultMLInference()
        self.logger = setup_security_logger()
        self.rules_engine = RulesEngine(get_account_func)

        app_config = getattr(self.app, "config", {}) or {}
        self.app_mode = app_config.get("APP_MODE") or os.getenv("APP_MODE", "vuln")

        if getattr(self.app, "logger", None):
            self.app.logger.info(f"Security Hook initialized in {self.app_mode} mode")

    def before_request_handler(self):
        try:
            g.request_start_time = time.time()
            context = SecurityContext()
            g.security_context = context

            if not self._should_analyze(context):
                return None

            resource_id = self._extract_resource_id(context.endpoint)
            if resource_id is None:
                return None

            idor_check = self.rules_engine.check_idor_attempt(context, resource_id)

            if idor_check.get("reason") in ("owner_mismatch", "owner_match"):
                g.owner_mismatch = idor_check.get("reason") == "owner_mismatch"

            if idor_check.get("is_violation"):
                context.is_suspicious = True
                context.violation_type = "idor_attempt"
                context.reason = idor_check.get("reason")

                risk_assessment = self._get_risk_score(context, resource_id)
                context.risk_score = risk_assessment["score"]
                context.confidence = risk_assessment["confidence"]
                context.top_feature = risk_assessment.get("top_feature", "none")

                if self.app_mode == "fixed":
                    context.decision = "block"
                    self._emit_security_event(context, resource_id, "idor_block")
                    return {
                        "error": "Forbidden",
                        "message": "Access denied",
                        "request_id": context.request_id,
                    }, 403

                context.decision = "allow"
                self._emit_security_event(context, resource_id, "idor_attempt")

            return None
        except Exception as exc:
            if getattr(self.app, "logger", None):
                self.app.logger.error(
                    f"Security hook error: {exc}\n{traceback.format_exc()}"
                )
            self._emit_error_event(str(exc))
            return None

    def after_request_handler(self, response):
        try:
            context = getattr(g, "security_context", None)
            if context and self._should_analyze(context):
                if not context.is_suspicious:
                    resource_id = self._extract_resource_id(context.endpoint)
                    self._emit_security_event(
                        context,
                        resource_id,
                        "account_access",
                        status_code=getattr(response, "status_code", None),
                    )
        except Exception as exc:
            if getattr(self.app, "logger", None):
                self.app.logger.error(f"After request hook error: {exc}")

        return response

    def _should_analyze(self, context):
        return context.endpoint.startswith("/api/accounts/")

    def _extract_resource_id(self, endpoint):
        try:
            parts = endpoint.split("/")
            if len(parts) >= 4 and parts[2] == "accounts":
                return int(parts[3])
        except (ValueError, IndexError):
            pass
        return None

    def _get_risk_score(self, context, resource_id):
        features = {
            "is_owner_mismatch": 1,
            "user_id": context.user_id,
            "resource_id": resource_id,
            "endpoint": context.endpoint,
            "user_agent": context.user_agent,
            "client_ip": context.client_ip,
            "request_rate_10s": 5,
            "resource_id_delta": 1,
            "has_suspicious_keyword": int(
                any(keyword in context.endpoint for keyword in ("admin", "login", "verify"))
            ),
            "domain_age_days": 365,
        }

        result = self.ml_inference.get_risk_score(features)
        return {
            "score": result.get("score") or result.get("risk_score") or "low",
            "confidence": result.get("confidence", 0.0),
            "top_feature": result.get("top_feature", "none"),
        }

    def _emit_security_event(self, context, resource_id, event_type, status_code=None):
        latency_ms = None
        if getattr(g, "request_start_time", None) is not None:
            latency_ms = int((time.time() - g.request_start_time) * 1000)

        event = {
            "event_type": event_type,
            "timestamp": context.timestamp,
            "request_id": context.request_id,
            "user_id": context.user_id,
            "role": context.role,
            "resource_type": "account",
            "resource_id": resource_id,
            "decision": context.decision,
            "reason": context.reason,
            "app_mode": self.app_mode,
            "client_ip": context.client_ip,
            "user_agent": context.user_agent,
            "risk_score": context.risk_score,
            "confidence": context.confidence,
            "top_feature": context.top_feature,
            "endpoint": context.endpoint,
            "method": context.method,
        }

        if status_code is not None:
            event["status_code"] = status_code
        if latency_ms is not None:
            event["latency_ms"] = latency_ms

        event["risk_intelligence"] = {
            "risk_score": context.risk_score,
            "confidence": context.confidence,
            "top_feature": context.top_feature,
        }

        log_security_event(self.logger, event)

    def _emit_error_event(self, error_message):
        event = {
            "event_type": "hook_error",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "error": error_message,
            "app_mode": self.app_mode,
        }
        log_security_event(self.logger, event)


def _get_default_account_func():
    try:
        from routes import get_account_by_id

        return get_account_by_id
    except Exception:
        return None


def register_security_hooks(app, get_account_func=None, ml_inference=None):
    """Attach runtime security hooks to a Flask app."""
    if get_account_func is None:
        get_account_func = _get_default_account_func()

    hook = SecurityHook(app, ml_inference or DefaultMLInference(), get_account_func)

    if not hasattr(app, "extensions"):
        app.extensions = {}
    app.extensions["security_hook"] = hook

    app.before_request(hook.before_request_handler)
    app.after_request(hook.after_request_handler)

    return hook
