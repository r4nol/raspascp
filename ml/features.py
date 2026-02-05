from typing import List, Dict, Any

def prepare_features(request_data: Dict[str, Any]) -> List[int]:
    """
    Конвертує контекст запиту у векторизований формат. 
    Включає базову валідацію типів.
    """
    return [
        int(request_data.get('is_owner_mismatch', 0)),
        int(request_data.get('request_rate_10s', 0)),
        int(request_data.get('resource_id_delta', 0)),
        int(request_data.get('has_suspicious_keyword', 0)),
        int(request_data.get('domain_age_days', 365))
    ]