"""
Main Anonymity Service - Orchestrates all components
Coordinates policy evaluation, proxy selection, and fingerprint protection
"""
import logging
from typing import Dict, Any, Optional
from datetime import datetime
from .policy_engine import PolicyEngine
from .proxy_manager import ProxyManager
from .fingerprint_manager import FingerprintManager


class AnonymityService:
    """
    Main orchestrator for the anonymity system
    Coordinates policy evaluation, proxy selection, and request execution
    """

    def __init__(self):
        """Initialize the anonymity service with all components"""
        self.policy_engine = PolicyEngine()
        self.proxy_manager = ProxyManager()
        self.fingerprint_manager = FingerprintManager()
        self.logger = logging.getLogger(__name__)
        self.request_history = []  # In production, this would be a database

    def process_anonymity_request(self, user_id: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process a complete anonymity request

        Args:
            user_id: Identifier for the requesting user
            request_data: Dictionary containing request details
                - target_url: URL to access anonymously
                - method: HTTP method (GET, POST, etc.)
                - headers: Additional headers
                - data: Request data for POST requests
                - preferences: User preferences for backend selection

        Returns:
            Dictionary containing the complete response and metadata
        """
        request_start_time = datetime.now()

        try:
            # Step 1: Policy Evaluation
            self.logger.info(f"Processing anonymity request for user {user_id}")

            # Add timestamp and user info to request data
            enriched_request_data = {
                **request_data,
                'timestamp': request_start_time.isoformat(),
                'user_id': user_id
            }

            policy_result = self.policy_engine.evaluate_anonymity_request(
                user_id=user_id,
                request_data=enriched_request_data
            )

            # Check if request is allowed by policy
            if not policy_result['allowed']:
                self.logger.warning(f"Request denied by policy: {policy_result['reason']}")
                return {
                    'success': False,
                    'error': 'Request denied by policy',
                    'reason': policy_result['reason'],
                    'risk_score': policy_result['risk_score'],
                    'timestamp': request_start_time.isoformat()
                }

            # Step 2: Backend Selection
            backend_preference = (
                request_data.get('preferences', {}).get('backend') or 
                policy_result.get('suggested_backend', 'auto')
            )

            proxy_config = self.proxy_manager.get_optimal_proxy(backend_preference)
            self.logger.info(f"Selected backend: {proxy_config['type']}")

            # Step 3: Fingerprint Protection & Request Execution
            use_fingerprint_protection = request_data.get('preferences', {}).get('fingerprint_protection', True)

            if use_fingerprint_protection:
                # Use browser-based protection (slower but more secure)
                response_data = self.fingerprint_manager.make_protected_request(
                    url=request_data['target_url'],
                    proxy_config=proxy_config,
                    method=request_data.get('method', 'GET'),
                    data=request_data.get('data'),
                    headers=request_data.get('headers')
                )
            else:
                # Use direct requests (faster but less protection)
                response_data = self._make_direct_request(
                    url=request_data['target_url'],
                    proxy_config=proxy_config,
                    method=request_data.get('method', 'GET'),
                    data=request_data.get('data'),
                    headers=request_data.get('headers')
                )

            # Step 4: Log Request and Return Results
            request_end_time = datetime.now()
            total_time = (request_end_time - request_start_time).total_seconds()

            # Log request for monitoring and analytics
            self._log_request(
                user_id=user_id,
                request_data=enriched_request_data,
                policy_result=policy_result,
                proxy_config=proxy_config,
                response_data=response_data,
                total_time=total_time
            )

            return {
                'success': response_data['success'],
                'response': response_data,
                'policy_metadata': policy_result,
                'backend_used': proxy_config['type'],
                'fingerprint_protection': use_fingerprint_protection,
                'total_time': total_time,
                'timestamp': request_start_time.isoformat()
            }

        except Exception as e:
            self.logger.error(f"Anonymity request processing failed: {str(e)}")
            return {
                'success': False,
                'error': f'Internal error: {str(e)}',
                'timestamp': request_start_time.isoformat()
            }

    def _make_direct_request(self, url: str, proxy_config: Dict[str, Any],
                           method: str = 'GET', data: Dict[str, Any] = None,
                           headers: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Make a direct HTTP request (without browser protection)
        """
        import requests
        import time

        try:
            start_time = time.time()

            # Prepare request parameters
            request_params = {
                'url': url,
                'method': method.upper(),
                'timeout': 30,
                'allow_redirects': True
            }

            if proxy_config.get('proxy'):
                request_params['proxies'] = proxy_config['proxy']

            if headers:
                request_params['headers'] = headers

            if data and method.upper() in ['POST', 'PUT', 'PATCH']:
                request_params['json'] = data

            # Make the request
            response = requests.request(**request_params)
            end_time = time.time()

            return {
                'success': True,
                'status_code': response.status_code,
                'content': response.text,
                'headers': dict(response.headers),
                'final_url': response.url,
                'response_time': end_time - start_time,
                'fingerprint_protection': False
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'fingerprint_protection': False
            }

    def _log_request(self, user_id: str, request_data: Dict[str, Any],
                    policy_result: Dict[str, Any], proxy_config: Dict[str, Any],
                    response_data: Dict[str, Any], total_time: float) -> None:
        """
        Log request for monitoring and analytics
        """
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'user_id': user_id,
            'target_url': request_data.get('target_url'),
            'method': request_data.get('method', 'GET'),
            'backend_used': proxy_config['type'],
            'success': response_data['success'],
            'response_time': total_time,
            'policy_risk_score': policy_result.get('risk_score', 0),
            'fingerprint_protection': response_data.get('fingerprint_protection', False)
        }

        # In production, this would write to a database
        self.request_history.append(log_entry)
        self.logger.info(f"Request logged: {log_entry}")

    def get_system_status(self) -> Dict[str, Any]:
        """
        Get comprehensive system status
        """
        return {
            'policy_engine': {
                'status': 'active',
                'opa_url': self.policy_engine.opa_url
            },
            'proxy_manager': self.proxy_manager.get_proxy_stats(),
            'fingerprint_manager': self.fingerprint_manager.get_fingerprint_stats(),
            'request_history_count': len(self.request_history),
            'system_uptime': 'Active'
        }

    def get_user_statistics(self, user_id: str) -> Dict[str, Any]:
        """
        Get statistics for a specific user
        """
        user_requests = [req for req in self.request_history if req['user_id'] == user_id]

        if not user_requests:
            return {'message': 'No requests found for this user'}

        total_requests = len(user_requests)
        successful_requests = len([req for req in user_requests if req['success']])
        avg_response_time = sum(req['response_time'] for req in user_requests) / total_requests

        backend_usage = {}
        for req in user_requests:
            backend = req['backend_used']
            backend_usage[backend] = backend_usage.get(backend, 0) + 1

        return {
            'total_requests': total_requests,
            'successful_requests': successful_requests,
            'success_rate': successful_requests / total_requests * 100,
            'average_response_time': avg_response_time,
            'backend_usage': backend_usage,
            'last_request': user_requests[-1]['timestamp'] if user_requests else None
        }
