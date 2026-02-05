import joblib
import os
import logging
import pandas as pd
import numpy as np

logger = logging.getLogger("RiskIntelligence")

class RiskModel:
    def __init__(self):
        self.feature_names = ['is_owner_mismatch', 'request_rate_10s', 'resource_id_delta', 'has_suspicious_keyword', 'domain_age_days']
        self.labels = {0: "low", 1: "medium", 2: "high"}
        self._load_model()

    def _load_model(self):
        # Використовуємо абсолютний шлях для стабільності
        base_dir = os.path.dirname(__file__)
        self.model_path = os.path.join(base_dir, 'model.pkl')
        try:
            self.model = joblib.load(self.model_path)
            logger.info("ML Model loaded successfully.")
        except:
            self.model = None

    def predict_risk(self, feature_vector):
        # Гарантуємо наявність ключів навіть при помилці
        result = {"risk_score": "low", "confidence": 0.0, "top_feature": "none"}
        
        if not self.model:
            return result

        try:
            # Створюємо DataFrame з іменами, щоб прибрати UserWarning
            x = pd.DataFrame([feature_vector], columns=self.feature_names)
            
            prediction = self.model.predict(x)[0]
            probs = self.model.predict_proba(x)[0]
            
            # Розрахунок впливу ознак (Feature Importance)
            # Дістаємо модель з Pipeline
            model_step = self.model.named_steps['model']
            scaler_step = self.model.named_steps['scaler']
            
            # Масштабуємо вектор так само, як при навчанні
            x_scaled = scaler_step.transform(x)[0]
            
            # Вплив = вага * значення
            impact = model_step.coef_[prediction] * x_scaled
            top_feature_idx = np.argmax(impact)
            
            result["risk_score"] = self.labels.get(prediction, "low")
            result["confidence"] = round(float(probs[prediction]), 2)
            result["top_feature"] = self.feature_names[top_feature_idx]
            
        except Exception as e:
            logger.error(f"Prediction error: {e}")
            
        return result

# Singleton
risk_engine = RiskModel()
