
import logging
import json
from datetime import datetime
import uuid
import os

class SecurityJSONFormatter(logging.Formatter):
    """Форматує логи як JSON для SIEM"""
    
    def format(self, record):
        # Базова структура події
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name
        }
        
        # Додаємо всі custom поля з record
        if hasattr(record, 'security_event'):
            log_data.update(record.security_event)
        else:
            log_data['message'] = record.getMessage()
        
        return json.dumps(log_data)


def setup_security_logger():
    """
    Налаштовує logger для security events
    Пише в /var/log/app/security.jsonl (JSON Lines format)
    """
    logger = logging.getLogger('security')
    logger.setLevel(logging.INFO)
    
    # Створюємо директорію якщо не існує
    log_dir = '/var/log/app'
    os.makedirs(log_dir, exist_ok=True)
    
    # File handler для JSON логів
    file_handler = logging.FileHandler(f'{log_dir}/security.jsonl')
    file_handler.setFormatter(SecurityJSONFormatter())
    logger.addHandler(file_handler)
    
    # Console handler для debug (опціонально)
    if os.getenv('DEBUG', 'false').lower() == 'true':
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(SecurityJSONFormatter())
        logger.addHandler(console_handler)
    
    logger.propagate = False  # Не передавати в root logger
    
    return logger


def log_security_event(logger, event_data):
    """
    Допоміжна функція для логування security події
    
    Args:
        logger: security logger instance
        event_data: dict з полями події (3.4 specification)
    """
    # Створюємо LogRecord з custom полями
    record = logger.makeRecord(
        logger.name,
        logging.INFO,
        fn='',
        lno=0,
        msg='',
        args=(),
        exc_info=None
    )
    record.security_event = event_data
    logger.handle(record)