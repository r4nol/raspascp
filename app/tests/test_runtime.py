
import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from security_hook import SecurityContext, RulesEngine, SecurityHook
from logging_conf import setup_security_logger


class TestSecurityContext(unittest.TestCase):
    """Test SecurityContext creation"""
    
    @patch('security_hook.request')
    @patch('security_hook.session')
    def test_context_creation(self, mock_session, mock_request):
        mock_session.get.side_effect = lambda k, d=None: {'user_id': 1, 'role': 'user'}.get(k, d)
        mock_request.path = '/api/accounts/5'
        mock_request.method = 'GET'
        mock_request.remote_addr = '192.168.1.1'
        mock_request.headers = {'User-Agent': 'curl/7.68.0'}
        
        ctx = SecurityContext()
        
        self.assertEqual(ctx.user_id, 1)
        self.assertEqual(ctx.role, 'user')
        self.assertEqual(ctx.endpoint, '/api/accounts/5')
        self.assertIsNotNone(ctx.request_id)


class TestRulesEngine(unittest.TestCase):
    """Test IDOR detection rules"""
    
    def setUp(self):
        # Mock get_account function
        self.accounts = {
            1: {'id': 1, 'owner_user_id': 1},
            2: {'id': 2, 'owner_user_id': 2}
        }
        self.get_account = lambda aid: self.accounts.get(aid)
        self.engine = RulesEngine(self.get_account)
    
    def test_idor_violation_detected(self):
        """User1 accessing User2's account = IDOR"""
        context = Mock()
        context.user_id = 1
        context.role = 'user'
        
        result = self.engine.check_idor_attempt(context, resource_id=2)
        
        self.assertTrue(result['is_violation'])
        self.assertEqual(result['reason'], 'owner_mismatch')
        self.assertEqual(result['resource_owner'], 2)
    
    def test_legitimate_access(self):
        """User1 accessing own account = OK"""
        context = Mock()
        context.user_id = 1
        context.role = 'user'
        
        result = self.engine.check_idor_attempt(context, resource_id=1)
        
        self.assertFalse(result['is_violation'])
        self.assertEqual(result['reason'], 'owner_match')
    
    def test_admin_can_access_all(self):
        """Admin accessing any account = OK"""
        context = Mock()
        context.user_id = 1
        context.role = 'admin'
        
        result = self.engine.check_idor_attempt(context, resource_id=2)
        
        self.assertFalse(result['is_violation'])
        self.assertEqual(result['reason'], 'admin_allowed')
    
    def test_unauthenticated_user(self):
        """Not logged in = skip check"""
        context = Mock()
        context.user_id = None
        context.role = 'anonymous'
        
        result = self.engine.check_idor_attempt(context, resource_id=1)
        
        self.assertFalse(result['is_violation'])
        self.assertEqual(result['reason'], 'not_authenticated')


class TestSecurityHook(unittest.TestCase):
    """Test SecurityHook integration"""
    
    def setUp(self):
        self.app = Mock()
        self.app.logger = Mock()
        
        # Mock ML
        self.ml = Mock()
        self.ml.get_risk_score.return_value = {
            'score': 'high',
            'confidence': 0.9
        }
        
        # Mock get_account
        self.accounts = {
            1: {'id': 1, 'owner_user_id': 1},
            2: {'id': 2, 'owner_user_id': 2}
        }
        self.get_account = lambda aid: self.accounts.get(aid)
    
    @patch.dict(os.environ, {'APP_MODE': 'fixed'})
    @patch('security_hook.session')
    @patch('security_hook.request')
    @patch('security_hook.g')
    def test_block_in_fixed_mode(self, mock_g, mock_request, mock_session):
        """In FIXED mode, IDOR should be blocked"""
        # Setup mocks
        mock_session.get.side_effect = lambda k, d=None: {'user_id': 1, 'role': 'user'}.get(k, d)
        mock_request.path = '/api/accounts/2'
        mock_request.method = 'GET'
        mock_request.remote_addr = '192.168.1.1'
        mock_request.headers = {}
        
        hook = SecurityHook(self.app, self.ml, self.get_account)
        
        response = hook.before_request_handler()
        
        # Should return 403
        self.assertIsNotNone(response)
        self.assertEqual(response[1], 403)
    
    @patch.dict(os.environ, {'APP_MODE': 'vuln'})
    @patch('security_hook.session')
    @patch('security_hook.request')
    @patch('security_hook.g')
    def test_allow_in_vuln_mode(self, mock_g, mock_request, mock_session):
        """In VULN mode, IDOR should be allowed (but logged)"""
        mock_session.get.side_effect = lambda k, d=None: {'user_id': 1, 'role': 'user'}.get(k, d)
        mock_request.path = '/api/accounts/2'
        mock_request.method = 'GET'
        mock_request.remote_addr = '192.168.1.1'
        mock_request.headers = {}
        
        hook = SecurityHook(self.app, self.ml, self.get_account)
        
        response = hook.before_request_handler()
        
        # Should NOT block (return None)
        self.assertIsNone(response)
        
        # But should have logged
        # (перевір що context.is_suspicious = True)


if __name__ == '__main__':
    unittest.main()