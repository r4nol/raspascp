import os
from flask import Flask

from logging_conf import configure_logging
from auth import setup_auth
from routes import setup_routes, get_account_by_id
from security_hook import register_security_hooks
from demo_ui import setup_demo_ui


def create_app():
    app = Flask(__name__)

    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")
    app.config["APP_MODE"] = os.environ.get("APP_MODE", "vuln")

    configure_logging(app)

    setup_auth(app)
    setup_routes(app)
    setup_demo_ui(app)

    app.config["GET_ACCOUNT_FUNC"] = get_account_by_id
    register_security_hooks(app, get_account_func=get_account_by_id)

    @app.route("/health")
    def health():
        return {"status": "ok", "app_mode": app.config["APP_MODE"]}, 200

    return app


app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("APP_PORT", os.environ.get("PORT", 5000)))
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    app.run(host="0.0.0.0", port=port, debug=debug)
