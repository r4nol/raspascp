import pandas as pd
import joblib
import logging
import os
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def train_ultimate_model():
    data = [
        [0, 1, 0, 0, 365, 0], [1, 1, 0, 0, 365, 1],
        [1, 5, 1, 0, 365, 2], [0, 20, 10, 1, 5, 2],
        [0, 1, 0, 1, 10, 1], [0, 2, 0, 0, 700, 0],
    ] * 200 
    
    cols = ['is_owner_mismatch', 'request_rate_10s', 'resource_id_delta', 
            'has_suspicious_keyword', 'domain_age_days', 'target']
    df = pd.DataFrame(data, columns=cols)
    
    # Видаляємо multi_class, щоб не було Warning
    pipe = Pipeline([
        ('scaler', StandardScaler()),
        ('model', LogisticRegression(
            class_weight='balanced',
            max_iter=1000
        ))
    ])
    
    pipe.fit(df.drop('target', axis=1), df['target'])
    
    path = os.path.join(os.path.dirname(__file__), 'model.pkl')
    joblib.dump(pipe, path)
    logging.info(f"✅ Pipeline saved to {path}")

if __name__ == "__main__":
    train_ultimate_model()