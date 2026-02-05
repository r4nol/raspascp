import base64
import json
import os
import time
from collections import deque
from copy import deepcopy
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from flask import Blueprint, current_app, jsonify, redirect, render_template, request, session

from logging_conf import _resolve_security_log_path
from routes import ACCOUNTS as ROUTE_ACCOUNTS
from routes import set_accounts
from security_hook import _ML_AVAILABLE


demo_bp = Blueprint("demo_ui", __name__)
DEFAULT_ACCOUNTS = deepcopy(ROUTE_ACCOUNTS)
_DEMO_TIMELINE = {
    "login": None,
    "request": None,
    "decision": None,
    "risk": None,
    "siem": None,
}


def _now_iso():
    return datetime.utcnow().isoformat() + "Z"


def _demo_access_code():
    return os.getenv("DEMO_ACCESS_CODE", "").strip()


def _demo_access_required():
    return bool(_demo_access_code())


def _demo_access_granted():
    return session.get("demo_access_granted") is True


def _require_demo_access():
    if _demo_access_required() and not _demo_access_granted():
        return jsonify({"error": "demo_access_required"}), 403
    return None


def _tail_security_events(limit=100):
    log_path = _resolve_security_log_path()
    if not log_path.exists():
        return []

    events = deque(maxlen=limit)
    try:
        with log_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    except Exception:
        return []

    return list(events)


def _reset_timeline():
    for key in list(_DEMO_TIMELINE.keys()):
        _DEMO_TIMELINE[key] = None


def _record_timeline(step):
    if step in _DEMO_TIMELINE:
        _DEMO_TIMELINE[step] = _now_iso()


def _safe_set_mode(mode):
    if mode in ("vuln", "fixed"):
        current_app.config["APP_MODE"] = mode
        hook = current_app.extensions.get("security_hook") if hasattr(current_app, "extensions") else None
        if hook is not None:
            hook.app_mode = mode


def _run_idor_sequence(requests_count=1):
    client = current_app.test_client()
    login_resp = client.post("/login", json={"username": "user1"})
    _record_timeline("login")

    if login_resp.status_code >= 400:
        return {
            "ok": False,
            "message": "Login failed",
            "status_code": login_resp.status_code,
        }

    results = []
    for idx in range(requests_count):
        resp = client.get("/api/accounts/1002")
        _record_timeline("request")
        results.append({
            "status_code": resp.status_code,
            "payload": resp.get_json(silent=True),
        })
        if idx < requests_count - 1:
            time.sleep(3)

    decision = "block" if any(r["status_code"] == 403 for r in results) else "allow"
    _DEMO_TIMELINE["decision"] = _now_iso()

    events = _tail_security_events(limit=5)
    if events:
        last_event = events[-1]
        if last_event.get("risk_score"):
            _record_timeline("risk")

    return {
        "ok": True,
        "message": "IDOR sequence completed",
        "decision": decision,
        "results": results,
    }


def _check_opensearch_health():
    url = os.getenv("SIEM_OPENSEARCH_URL") or os.getenv("OPENSEARCH_URL")
    if not url:
        return {
            "state": "not_configured",
            "message": "Set OPENSEARCH_URL to enable checks",
        }

    target = url.rstrip("/") + "/_cluster/health"
    headers = {"User-Agent": "ascp-demo"}
    username = os.getenv("OPENSEARCH_USERNAME")
    password = os.getenv("OPENSEARCH_PASSWORD")
    if username and password:
        token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("utf-8")
        headers["Authorization"] = f"Basic {token}"

    req = Request(target, headers=headers)
    try:
        with urlopen(req, timeout=2) as response:
            if 200 <= response.status < 400:
                return {"state": "healthy", "message": "OpenSearch reachable"}
    except (HTTPError, URLError, ValueError):
        return {
            "state": "unreachable",
            "message": "OpenSearch not reachable",
        }

    return {
        "state": "degraded",
        "message": "OpenSearch responded unexpectedly",
    }


@demo_bp.route("/")
def landing():
    return render_template("landing.html")


@demo_bp.route("/demo")
def demo():
    if _demo_access_required() and not _demo_access_granted():
        return render_template("demo_gate.html", error=None)
    return render_template("demo.html")


@demo_bp.route("/demo/access", methods=["POST"])
def demo_access():
    code = request.form.get("access_code", "").strip()
    if code and code == _demo_access_code():
        session["demo_access_granted"] = True
        return redirect("/demo")

    return render_template("demo_gate.html", error="Invalid access code")


@demo_bp.route("/api/demo/status")
def demo_status():
    access_check = _require_demo_access()
    if access_check:
        return access_check

    app_mode = current_app.config.get("APP_MODE", "vuln")
    log_path = _resolve_security_log_path()
    log_ready = log_path.exists()

    return jsonify({
        "app": {
            "state": "healthy",
            "app_mode": app_mode,
            "message": "Runtime hook active",
        },
        "ml": {
            "state": "healthy" if _ML_AVAILABLE else "fallback",
            "message": "ML inference ready" if _ML_AVAILABLE else "Fallback scoring in use",
        },
        "siem": _check_opensearch_health(),
        "slack": {
            "state": "configured" if os.getenv("SLACK_WEBHOOK_URL") else "not_configured",
            "message": "Webhook detected" if os.getenv("SLACK_WEBHOOK_URL") else "Set SLACK_WEBHOOK_URL",
        },
        "security_log": {
            "state": "ready" if log_ready else "missing",
            "message": "Security log file available" if log_ready else "No security.jsonl yet",
        },
        "timeline": _DEMO_TIMELINE,
    })


@demo_bp.route("/api/demo/events")
def demo_events():
    access_check = _require_demo_access()
    if access_check:
        return access_check

    try:
        limit = int(request.args.get("limit", 100))
    except ValueError:
        limit = 100

    limit = max(1, min(limit, 500))
    events = _tail_security_events(limit=limit)

    return jsonify({"events": events})


@demo_bp.route("/api/demo/mode", methods=["POST"])
def demo_mode():
    access_check = _require_demo_access()
    if access_check:
        return access_check

    payload = request.get_json(silent=True) or {}
    mode = (
        request.args.get("mode")
        or request.form.get("mode")
        or payload.get("mode")
    )
    if mode not in ("vuln", "fixed"):
        return jsonify({"error": "invalid_mode"}), 400

    _safe_set_mode(mode)
    return jsonify({"mode": current_app.config.get("APP_MODE", "vuln")})


@demo_bp.route("/api/demo/run", methods=["POST"])
def demo_run():
    access_check = _require_demo_access()
    if access_check:
        return access_check

    run_type = request.args.get("type", "single")
    mode = request.args.get("mode")
    if mode:
        _safe_set_mode(mode)

    _reset_timeline()

    if run_type == "burst":
        result = _run_idor_sequence(requests_count=3)
    else:
        result = _run_idor_sequence(requests_count=1)

    if not result.get("ok"):
        return jsonify({
            "error": result.get("message", "Run failed"),
            "timeline": _DEMO_TIMELINE,
        }), 500

    return jsonify({
        "message": result.get("message"),
        "decision": result.get("decision"),
        "timeline": _DEMO_TIMELINE,
    })


@demo_bp.route("/api/demo/reset", methods=["POST"])
def demo_reset():
    access_check = _require_demo_access()
    if access_check:
        return access_check

    set_accounts(deepcopy(DEFAULT_ACCOUNTS))
    _reset_timeline()

    log_path = _resolve_security_log_path()
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("")
    except Exception:
        pass

    return jsonify({"status": "reset"})


def setup_demo_ui(app):
    app.register_blueprint(demo_bp)
    return app
