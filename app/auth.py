from flask import Blueprint, request, session, jsonify
import uuid
import logging

auth_bp = Blueprint("auth", __name__)
logger = logging.getLogger("app")

# --- In-memory users (demo only) ---
USERS = {
    "user1": {
        "id": 1,
        "username": "user1",
        "role": "user"
    },
    "user2": {
        "id": 2,
        "username": "user2",
        "role": "user"
    },
    "admin": {
        "id": 99,
        "username": "admin",
        "role": "admin"
    }
}


@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Demo login:
    POST /login
    Body: { "username": "user1" }
    """
    data = request.get_json(silent=True) or {}
    username = data.get("username")

    if not username or username not in USERS:
        return jsonify({"error": "Invalid credentials"}), 401

    user = USERS[username]

    # --- Create session ---
    session.clear()
    session["user_id"] = user["id"]
    session["role"] = user["role"]
    session["request_id"] = str(uuid.uuid4())

    logger.info(
        "User logged in",
        extra={
            "event_type": "auth",
            "action": "login",
            "user_id": user["id"],
            "role": user["role"],
            "username": user["username"]
        }
    )

    return jsonify({
        "message": "login successful",
        "user_id": user["id"],
        "role": user["role"]
    }), 200


@auth_bp.route("/logout", methods=["POST"])
def logout():
    user_id = session.get("user_id")

    session.clear()

    logger.info(
        "User logged out",
        extra={
            "event_type": "auth",
            "action": "logout",
            "user_id": user_id
        }
    )

    return jsonify({"message": "logged out"}), 200
