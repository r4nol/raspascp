from flask import Blueprint, jsonify, session, current_app, request, g
import logging

api_bp = Blueprint("api", __name__)
logger = logging.getLogger("app")

# --- In-memory demo data ---
ACCOUNTS = {
    1001: {
        "id": 1001,
        "owner_user_id": 1,
        "iban": "UA111111111111111111111111111",
        "balance": 1500.00
    },
    1002: {
        "id": 1002,
        "owner_user_id": 2,
        "iban": "UA222222222222222222222222222",
        "balance": 3200.50
    }
}


def set_accounts(accounts):
    """Override in-memory accounts store (demo only)."""
    global ACCOUNTS
    ACCOUNTS = accounts or {}


def get_account_by_id(account_id):
    """Helper for security hook / other modules."""
    return ACCOUNTS.get(account_id)


def _unauthorized():
    return jsonify({"error": "unauthorized"}), 401


@api_bp.route("/api/me", methods=["GET"])
def api_me():
    if "user_id" not in session:
        return _unauthorized()

    return jsonify({
        "user_id": session.get("user_id"),
        "role": session.get("role")
    }), 200


@api_bp.route("/api/accounts/<int:account_id>", methods=["GET"])
def get_account(account_id):
    """
    IDOR demo endpoint
    """
    if "user_id" not in session:
        return _unauthorized()

    account = ACCOUNTS.get(account_id)
    if not account:
        return jsonify({"error": "account not found"}), 404

    user_id = session.get("user_id")
    role = session.get("role")
    app_mode = current_app.config.get("APP_MODE", "vuln")

    owner_mismatch = account["owner_user_id"] != user_id
    g.owner_mismatch = owner_mismatch

    # --- FIXED MODE: enforce authorization ---
    if app_mode == "fixed":
        if role != "admin" and owner_mismatch:
            logger.warning(
                "IDOR blocked",
                extra={
                    "event_type": "idor_block",
                    "user_id": user_id,
                    "role": role,
                    "resource_type": "account",
                    "resource_id": account_id,
                    "decision": "block",
                    "reason": "owner_mismatch",
                    "endpoint": request.path
                }
            )
            return jsonify({"error": "forbidden"}), 403

    # --- VULN MODE: allow access even on mismatch ---
    logger.info(
        "Account accessed",
        extra={
            "event_type": "idor_attempt" if owner_mismatch else "info",
            "user_id": user_id,
            "role": role,
            "resource_type": "account",
            "resource_id": account_id,
            "decision": "allow",
            "reason": "owner_mismatch" if owner_mismatch else "owner_match",
            "endpoint": request.path
        }
    )

    return jsonify({
        "id": account["id"],
        "owner_user_id": account["owner_user_id"],
        "iban": account["iban"],
        "balance": account["balance"]
    }), 200


def setup_routes(app, accounts=None, get_account_func=None):
    """
    Register API blueprint on the app.
    Allows overriding accounts for demos/tests.
    """
    if accounts is not None:
        set_accounts(accounts)
    if get_account_func is not None:
        app.config["GET_ACCOUNT_FUNC"] = get_account_func
    app.register_blueprint(api_bp)
    return app
