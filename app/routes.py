from flask import Blueprint, jsonify, session, current_app, request
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
