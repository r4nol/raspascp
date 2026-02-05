# При записі логу в JSON додаємо цей блок:
log_entry = {
    "timestamp": "...",
    "user_id": user_id,
    "event": "api_access",
    "risk_intelligence": {
        "risk_score": ml_result['risk_score'],
        "confidence": ml_result['confidence'],
        "top_feature": ml_result['top_feature']
    }
}