"""
Flask Application
З інтегрованим Runtime Security Hook
"""
from flask import Flask, session, jsonify
import os

# Імпорти від інших команд
from routes import setup_routes  # App команда робить це
from auth import setup_auth      # App команда робить це

# ТВОЇ ІМПОРТИ
from security_hook import SecurityHook

# ML імпорт (від ML команди)
# Узгодь інтерфейс з ними!
try:
    from ml.model_infer import MLInference
    ml_available = True
except ImportError:
    ml_available = False
    print("WARNING: ML module not available, using fallback")


app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'dev-secret-key-change-me')

# ===== APP КОМАНДА РОБИТЬ ЦЕ =====
# Налаштування auth, routes, database
setup_auth(app)

# In-memory "database" (App команда може зробити sqlite)
ACCOUNTS = {
    1: {'id': 1, 'owner_user_id': 1, 'balance': 1000.0, 'iban': 'UA123456789'},
    2: {'id': 2, 'owner_user_id': 2, 'balance': 2500.0, 'iban': 'UA987654321'},
    3: {'id': 3, 'owner_user_id': 1, 'balance': 500.0, 'iban': 'UA111222333'}
}

def get_account(account_id):
    """Функція для отримання account - потрібна для security hook"""
    return ACCOUNTS.get(account_id)

setup_routes(app, ACCOUNTS, get_account)


# ===== ТВІЙ КОД ПОЧИНАЄТЬСЯ ТУТ =====

# Ініціалізація ML
if ml_available:
    ml_inference = MLInference()
else:
    # Fallback якщо ML ще не готовий
    class DummyML:
        def get_risk_score(self, features):
            # Проста евристика
            if features.get('is_owner_mismatch'):
                return {'score': 'high', 'confidence': 0.8}
            return {'score': 'low', 'confidence': 0.3}
    
    ml_inference = DummyML()

# Ініціалізація Security Hook
security_hook = SecurityHook(
    app=app,
    ml_inference=ml_inference,
    get_account_func=get_account
)

# Інтеграція в Flask
@app.before_request
def security_check():
    """Runtime security analysis"""
    return security_hook.before_request_handler()

@app.after_request
def security_log(response):
    """Log security events"""
    return security_hook.after_request_handler(response)

# ===== ТВІЙ КОД ЗАКІНЧУЄТЬСЯ ТУТ =====


if __name__ == '__main__':
    mode = os.getenv('APP_MODE', 'vuln')
    print(f"🚀 Starting app in {mode} mode")
    print(f"🔒 Security Hook: {'ENABLED' if security_hook else 'DISABLED'}")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=os.getenv('DEBUG', 'false').lower() == 'true'
    )