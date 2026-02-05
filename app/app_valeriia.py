import os
from flask import Flask
from logging_conf import configure_logging
from auth import auth_bp
from routes import api_bp
from security_hook import register_security_hooks


def create_app():
    app = Flask(__name__)

    # --- Basic config ---
    app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret-key")
    app.config["APP_MODE"] = os.environ.get("APP_MODE", "vuln")  # vuln | fixed

    # --- Logging ---
    configure_logging(app)

    # --- Blueprints ---
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)

    # --- Runtime security hooks
    register_security_hooks(app)

    @app.route("/health")
    def health():
        return {
            "status": "ok",
            "app_mode": app.config["APP_MODE"]
        }, 200

    return app


app = create_app()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=False
    )
