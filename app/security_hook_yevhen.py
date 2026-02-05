
from flask import request, session, g, jsonify
import uuid
from datetime import datetime
import os
import traceback
from logging_conf import setup_security_logger, log_security_event


class SecurityContext:
    """Контекст для одного HTTP запиту"""
    
    def __init__(self):
        self.request_id = str(uuid.uuid4())
        self.timestamp = datetime.utcnow().isoformat() + 'Z'
        self.user_id = session.get('user_id')
        self.role = session.get('role', 'anonymous')
        self.endpoint = request.path
        self.method = request.method
        self.client_ip = request.remote_addr
        self.user_agent = request.headers.get('User-Agent', '')
        
        # Runtime analysis results
        self.is_suspicious = False
        self.violation_type = None
        self.decision = 'allow'
        self.reason = None
        self.risk_score = 'low'
        self.confidence = 0.0


class RulesEngine:
    """
    Перевіряє правила безпеки
    Розділ 3.3 - Правило R1 (IDOR Detection)
    """
    
    def __init__(self, get_account_func):
        """
        Args:
            get_account_func: функція щоб отримати account by ID
                              повертає dict з полем 'owner_user_id'
        """
        self.get_account = get_account_func
    
    def check_idor_attempt(self, context, resource_id):
        """
        Правило R1: IDOR Detection
        
        Умови:
        - endpoint /api/accounts/<id>
        - користувач залогінений
        - роль = 'user' (не admin)
        - account.owner_user_id != session.user_id
        
        Returns:
            dict: {
                'is_violation': bool,
                'reason': str,
                'resource_owner': int
            }
        """
        # Якщо не залогінений - пропускаємо (це обробляє auth)
        if not context.user_id:
            return {'is_violation': False, 'reason': 'not_authenticated'}
        
        # Admin може все
        if context.role == 'admin':
            return {'is_violation': False, 'reason': 'admin_allowed'}
        
        # Отримуємо account
        try:
            account = self.get_account(resource_id)
            if not account:
                return {'is_violation': False, 'reason': 'resource_not_found'}
            
            # ПЕРЕВІРКА: owner_user_id == requester?
            owner_id = account.get('owner_user_id')
            if owner_id != context.user_id:
                return {
                    'is_violation': True,
                    'reason': 'owner_mismatch',
                    'resource_owner': owner_id
                }
            
            return {'is_violation': False, 'reason': 'owner_match'}
            
        except Exception as e:
            # Fail-open: при помилці не блокуємо
            return {
                'is_violation': False, 
                'reason': f'check_error: {str(e)}'
            }


class SecurityHook:
    """
    Головний Runtime Security Hook
    Інтегрується в Flask через before_request/after_request
    """
    
    def __init__(self, app, ml_inference, get_account_func):
        """
        Args:
            app: Flask app instance
            ml_inference: ML модуль для risk scoring
            get_account_func: функція для отримання account
        """
        self.app = app
        self.ml_inference = ml_inference
        self.logger = setup_security_logger()
        self.rules_engine = RulesEngine(get_account_func)
        
        # Режим роботи
        self.app_mode = os.getenv('APP_MODE', 'vuln')  # vuln|fixed
        
        self.app.logger.info(f"Security Hook initialized in {self.app_mode} mode")
    
    def before_request_handler(self):
        """
        Викликається ПЕРЕД кожним запитом
        Аналізує і можливо блокує
        
        Returns:
            None - дозволити запит
            Response - заблокувати з цією відповіддю
        """
        try:
            # Створюємо контекст запиту
            context = SecurityContext()
            g.security_context = context  # Зберігаємо для after_request
            
            # Перевіряємо чи це endpoint який нас цікавить
            if not self._should_analyze(context):
                return None
            
            # Витягуємо resource_id з URL
            resource_id = self._extract_resource_id(context.endpoint)
            if not resource_id:
                return None
            
            # ПРАВИЛО R1: IDOR Detection
            idor_check = self.rules_engine.check_idor_attempt(context, resource_id)
            
            if idor_check['is_violation']:
                # Знайдено IDOR спробу!
                context.is_suspicious = True
                context.violation_type = 'idor_attempt'
                context.reason = idor_check['reason']
                
                # ML Risk Scoring
                risk_assessment = self._get_risk_score(context, resource_id)
                context.risk_score = risk_assessment['score']
                context.confidence = risk_assessment['confidence']
                
                # Рішення: блокувати чи ні
                if self.app_mode == 'fixed':
                    context.decision = 'block'
                    self._emit_security_event(context, resource_id, 'idor_block')
                    
                    # БЛОКУЄМО
                    return jsonify({
                        'error': 'Forbidden',
                        'message': 'Access denied',
                        'request_id': context.request_id
                    }), 403
                else:
                    # vuln mode - дозволяємо але логуємо
                    context.decision = 'allow'
                    self._emit_security_event(context, resource_id, 'idor_attempt')
            
            return None  # Продовжити нормальну обробку
            
        except Exception as e:
            # FAIL-OPEN: при помилці не валимо app
            self.app.logger.error(f"Security hook error: {e}\n{traceback.format_exc()}")
            self._emit_error_event(str(e))
            return None
    
    def after_request_handler(self, response):
        """
        Викликається ПІСЛЯ обробки запиту
        Логує результат
        """
        try:
            context = getattr(g, 'security_context', None)
            if context and self._should_analyze(context):
                # Логуємо успішний запит якщо він був дозволений
                if not context.is_suspicious:
                    resource_id = self._extract_resource_id(context.endpoint)
                    self._emit_security_event(
                        context, 
                        resource_id, 
                        'account_access',
                        status_code=response.status_code
                    )
        except Exception as e:
            self.app.logger.error(f"After request hook error: {e}")
        
        return response
    
    def _should_analyze(self, context):
        """Чи потрібно аналізувати цей запит"""
        # Аналізуємо тільки /api/accounts/*
        return context.endpoint.startswith('/api/accounts/')
    
    def _extract_resource_id(self, endpoint):
        """Витягує ID з /api/accounts/<id>"""
        try:
            parts = endpoint.split('/')
            # /api/accounts/123 -> parts = ['', 'api', 'accounts', '123']
            if len(parts) >= 4 and parts[2] == 'accounts':
                return int(parts[3])
        except (ValueError, IndexError):
            pass
        return None
    
    def _get_risk_score(self, context, resource_id):
        """
        Викликає ML модуль для risk scoring
        
        Returns:
            dict: {'score': 'low|medium|high', 'confidence': float}
        """
        try:
            # Збираємо features для ML
            features = {
                'is_owner_mismatch': 1,  # Ми вже знаємо що це violation
                'user_id': context.user_id,
                'resource_id': resource_id,
                'endpoint': context.endpoint,
                'user_agent': context.user_agent,
                'client_ip': context.client_ip
            }
            
            # Викликаємо ML inference
            return self.ml_inference.get_risk_score(features)
            
        except Exception as e:
            # Fallback якщо ML не працює
            self.app.logger.warning(f"ML inference failed: {e}")
            return {'score': 'medium', 'confidence': 0.5}
    
    def _emit_security_event(self, context, resource_id, event_type, status_code=None):
        """
        Генерує security event у форматі 3.4
        Пише в security.jsonl
        """
        event = {
            # Required fields (3.4)
            'event_type': event_type,
            'timestamp': context.timestamp,
            'request_id': context.request_id,
            'user_id': context.user_id,
            'role': context.role,
            'resource_type': 'account',
            'resource_id': resource_id,
            'decision': context.decision,
            'reason': context.reason,
            'app_mode': self.app_mode,
            'client_ip': context.client_ip,
            'user_agent': context.user_agent,
            
            # ML fields
            'risk_score': context.risk_score,
            'confidence': context.confidence,
            
            # Additional context
            'endpoint': context.endpoint,
            'method': context.method
        }
        
        if status_code:
            event['status_code'] = status_code
        
        log_security_event(self.logger, event)
    
    def _emit_error_event(self, error_message):
        """Логує помилку в security hook"""
        event = {
            'event_type': 'hook_error',
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'error': error_message,
            'app_mode': self.app_mode
        }
        log_security_event(self.logger, event)