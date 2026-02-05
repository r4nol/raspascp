# 🧠 ML Risk Intelligence Module

Цей модуль є інтелектуальним компонентом системи **Adaptive Security Control Plane (ASCP)**. Він відповідає за аналіз поведінкових ознак запитів у реальному часі та генерацію оцінки ризику (`risk_score`) для SIEM-системи.

## 📌 Огляд
Модуль реалізовано на базі **Machine Learning Pipeline**, що дозволяє автоматизувати обробку даних та класифікацію загроз (зокрема IDOR та Brute-force атак).

### Ключові особливості:
* **Explainable AI:** Модель не просто дає оцінку, а й визначає `top_feature` (головний фактор ризику).
* **Fail-Open Architecture:** Якщо модель недоступна, система переходить на безпечний rule-based fallback, не зупиняючи роботу API.
* **Feature Scaling:** Використання `StandardScaler` гарантує точність незалежно від масштабу вхідних значень.

## 🛠 Технічний стек
* **Core:** Python 3.12
* **Model:** Logistic Regression (Multinomial)
* **Pipeline:** Scikit-learn Pipeline (Scaler + Model)
* **Persistence:** Joblib

## 📊 Feature Set (Ознаки)
Модель аналізує 5 ключових метрик:
1.  `is_owner_mismatch` (0/1): Розбіжність між власником ресурсу та сесією.
2.  `request_rate_10s`: Кількість запитів від користувача за останні 10 секунд.
3.  `resource_id_delta`: Абсолютна різниця між поточним та попереднім ID ресурсу.
4.  `has_suspicious_keyword`: Наявність ключових слів (`admin`, `login`, `verify`) у URL.
5.  `domain_age_days`: Вік домену (заглушка для аналізу репутації).

## 🚀 Відповідність ТЗ (Acceptance Criteria)
Згідно з п. 4.5 ToR, модель демонструє такі результати:
* **Single IDOR:** `MEDIUM` (0.96+ confidence)
* **Series IDOR (>=3 req):** `HIGH` (1.0 confidence)
* **Normal Traffic:** `LOW` (0.98+ confidence)

## 📂 Структура файлів
* `model_train.py`: Скрипт навчання. Використовує `class_weight='balanced'` для коректної роботи з рідкісними атаками.
* `model_infer.py`: Клас-інтерфейс `RiskModel`. Забезпечує Singleton-інстанс для Flask.
* `features.py`: Модуль підготовки та валідації вхідних векторів.
* `model.pkl`: Серіалізований навчений Pipeline.

## ⚙️ Використання
1. **Навчання:**
   `python ml/model_train.py`
2. **Інтеграція:**
   Результати ML автоматично записуються у `security.jsonl` лог.
