from ml.model_infer import risk_engine
from ml.features import prepare_features

def check_access_with_ml(user_id, owner_id):
    # Готуємо дані для моделі
    context = {
        "is_owner_mismatch": int(user_id != owner_id),
        "request_rate_10s": 5, # Тут має бути реальний лічильник запитів
        "resource_id_delta": 1,
        "has_suspicious_keyword": 0,
        "domain_age_days": 365
    }
    
    # Отримуємо вердикт від ML
    vector = prepare_features(context)
    ml_result = risk_engine.predict_risk(vector)
    
    # Логіка блокування: якщо ризик HIGH — блокуємо
    if ml_result['risk_score'] == 'high':
        return False, ml_result
    return True, ml_result