"""
Anonymity Service - Core service for processing anonymous requests
Routes requests through appropriate backends based on policy decisions
"""

import logging
import time
import requests
import uuid
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class AnonymityService:
    """
    Main service for processing anonymous web requests.
    
    Responsibilities:
    - Evaluate requests against Rego/OPA policies
    - Route traffic through appropriate backend (Tor, Direct, etc.)
    - Apply fingerprint protection when enabled
    - Track user statistics
    """
    
    def __init__(self):
        # Import services (lazy loading to avoid circular imports)
        from app.services.policy_engine import PolicyEngine
        from app.services.fingerprint_manager import FingerprintManager
        from app.services.proxy_manager import ProxyManager
        
        self.policy_engine = PolicyEngine()
        self.fingerprint_manager = FingerprintManager()
        self.proxy_manager = ProxyManager()
        
        # User statistics storage (in production, use Redis/database)
        self.user_stats = {}
        
        # Request history storage (for system status)
        self.request_history: List[Dict] = []
        
        # Tor SOCKS5 proxy configuration
        self.tor_proxy = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        
        logger.info("AnonymityService initialized")
    
    @staticmethod
    def _generate_request_id() -> str:
        """Generate a unique request ID"""
        return str(uuid.uuid4())[:8]
    
    @staticmethod
    def _is_valid_url(url: str) -> tuple:
        """Validate URL format"""
        try:
            result = urlparse(url)
            if all([result.scheme, result.netloc]):
                if result.scheme in ['http', 'https']:
                    return True, "Valid URL"
            return False, "Invalid URL scheme or format"
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def _extract_domain(url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return url
    
    @staticmethod
    def _domain_requires_tor(domain: str) -> bool:
        """
        Check if a domain REQUIRES Tor to be accessed.
        These domains cannot be resolved by regular DNS.
        
        Args:
            domain: The domain name to check
            
        Returns:
            True if the domain requires Tor, False otherwise
        """
        if not domain:
            return False
        
        domain_lower = domain.lower()
        
        # TLDs that require Tor or special networks
        tor_required_tlds = [
            '.onion',      # Tor hidden services
            '.i2p',        # I2P network
            '.loki',       # Lokinet
            '.bit',        # Namecoin (often accessed via Tor)
        ]
        
        for tld in tor_required_tlds:
            if domain_lower.endswith(tld):
                return True
        
        return False
    
    def _log_request(self, request_id: str, user_id: str, request_data: Dict,
                     policy_result: Dict, proxy_config: Dict, response_data: Dict,
                     total_time: float, policy_time: float, execution_time: float,
                     risk_level: str):
        """Log request details for history and analytics"""
        log_entry = {
            'request_id': request_id,
            'user_id': user_id[:8] if user_id else 'unknown',
            'target_url': request_data.get('target_url', ''),
            'target_domain': self._extract_domain(request_data.get('target_url', '')),
            'method': request_data.get('method', 'GET'),
            'backend_used': proxy_config.get('type', 'unknown'),
            'risk_level': risk_level,
            'risk_score': policy_result.get('risk_score', 0),
            'success': response_data.get('success', False),
            'status_code': response_data.get('status_code'),
            'total_time': total_time,
            'policy_time': policy_time,
            'execution_time': execution_time,
            'timestamp': datetime.now().isoformat()
        }
        
        # Add to history (keep last 100 entries)
        self.request_history.insert(0, log_entry)
        if len(self.request_history) > 100:
            self.request_history = self.request_history[:100]
        
        logger.info(f"[{request_id}] Request logged: {risk_level} risk, "
                   f"{proxy_config.get('type')} backend, {total_time:.2f}s")
    
    def get_system_status(self) -> Dict[str, Any]:
        """
        Get comprehensive system status
        """
        # Check Tor connectivity
        tor_status = self._check_tor_connectivity()
        
        return {
            'policy_engine': {
                'status': 'active',
                'active': True,
                'opa_url': self.policy_engine.opa_url,
                'healthy': self.policy_engine.check_health(),
                'policies_loaded': self.policy_engine.policies_loaded,
                'policy_count': self.policy_engine.policy_count,
                'last_evaluation': self.policy_engine.last_evaluation_time,
                'risk_thresholds': self.policy_engine.risk_thresholds
            },
            'proxy_manager': self.proxy_manager.get_status(),
            'fingerprint_manager': self.fingerprint_manager.get_fingerprint_stats(),
            'tor_connectivity': tor_status,
            'request_history_count': len(self.request_history),
            'system_uptime': 'Active',
            'timestamp': datetime.now().isoformat()
        }
    
    def _check_tor_connectivity(self) -> Dict[str, Any]:
        """
        Quick check if Tor is working
        """
        try:
            import requests
            proxies = {
                'http': f'socks5h://127.0.0.1:9050',
                'https': f'socks5h://127.0.0.1:9050'
            }
            response = requests.get(
                'https://check.torproject.org/api/ip',
                proxies=proxies,
                timeout=10
            )
            data = response.json()
            return {
                'connected': True,
                'is_tor': data.get('IsTor', False),
                'exit_ip': data.get('IP', 'Unknown')
            }
        except Exception as e:
            logger.debug(f"Tor connectivity check failed: {e}")
            return {
                'connected': False,
                'is_tor': False,
                'error': str(e)
            }
    
    def get_user_statistics(self, user_id):
        """Get statistics for a specific user session"""
        if user_id not in self.user_stats:
            self.user_stats[user_id] = self._create_empty_stats()
        return self.user_stats[user_id]
    
    def _create_empty_stats(self):
        """Create empty statistics structure"""
        return {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'backend_usage': {
                'tor': 0,
                'direct': 0,
                'proxy': 0,
                'vpn': 0
            },
            'total_response_time': 0,
            'average_response_time': 0,
            'success_rate': 0,
            'last_request': None
        }
    
    def _update_stats(self, user_id, success, backend, response_time):
        """Update user statistics after a request"""
        if user_id not in self.user_stats:
            self.user_stats[user_id] = self._create_empty_stats()
        
        stats = self.user_stats[user_id]
        stats['total_requests'] += 1
        
        if success:
            stats['successful_requests'] += 1
        else:
            stats['failed_requests'] += 1
        
        # Update backend usage
        backend_key = backend.lower() if backend else 'direct'
        if backend_key in stats['backend_usage']:
            stats['backend_usage'][backend_key] += 1
        
        # Update response time
        stats['total_response_time'] += response_time
        stats['average_response_time'] = stats['total_response_time'] / stats['total_requests']
        
        # Update success rate
        stats['success_rate'] = (stats['successful_requests'] / stats['total_requests']) * 100
        
        # Update last request timestamp
        stats['last_request'] = datetime.now().isoformat()
    
    def process_anonymity_request(self, user_id: str, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process an anonymity request through the full pipeline.
        """
        request_id = self._generate_request_id()
        request_start_time = datetime.now()
        
        logger.info(f"[{request_id}] Processing anonymity request for user {user_id[:8]}...")
        
        try:
            # Validate the target URL
            target_url = request_data.get('target_url', '')
            is_valid, validation_msg = self._is_valid_url(target_url)
            if not is_valid:
                return {
                    'success': False,
                    'error': f'Invalid URL: {validation_msg}',
                    'request_id': request_id,
                    'timestamp': request_start_time.isoformat()
                }
            
            target_domain = self._extract_domain(target_url)
            
            # Step 1: Policy Evaluation
            policy_start = datetime.now()
            
            # Build enriched request data for policy evaluation
            enriched_request_data = {
                'target_url': target_url,
                'target_domain': target_domain,
                'method': request_data.get('method', 'GET'),
                'user_id': user_id,
                'timestamp': request_start_time.isoformat()
            }
            
            policy_result = self.policy_engine.evaluate_request(enriched_request_data)
            policy_time = (datetime.now() - policy_start).total_seconds()
            
            logger.info(f"[{request_id}] Policy result: risk={policy_result['risk_level']}, "
                       f"suggested_backend={policy_result['suggested_backend']}")
            
            # Step 2: Backend Selection
            # User preference takes precedence, but policy can override for safety
            user_backend_pref = request_data.get('preferences', {}).get('backend', 'auto')
            policy_suggested = policy_result.get('suggested_backend', 'tor')
            
            # Check if domain REQUIRES Tor (e.g., .onion domains)
            requires_tor = self._domain_requires_tor(target_domain)
            
            # Determine actual backend to use
            if requires_tor:
                # .onion and other special domains MUST use Tor - no exceptions
                backend_preference = 'tor'
                logger.info(f"[{request_id}] Forcing Tor for special domain: {target_domain}")
            elif user_backend_pref == 'auto':
                # Auto mode: use policy suggestion
                backend_preference = policy_suggested
            elif user_backend_pref == 'direct' and policy_result['risk_level'] in ['high', 'critical']:
                # User wants direct but site is risky - override to Tor for safety
                backend_preference = 'tor'
                logger.warning(f"[{request_id}] Overriding direct to tor due to high risk")
            else:
                # Use user preference
                backend_preference = user_backend_pref
            
            proxy_config = self.proxy_manager.get_optimal_proxy(backend_preference)
            logger.info(f"[{request_id}] Selected backend: {proxy_config['type']}")
            
            # Step 3: Fingerprint Protection & Request Execution
            use_fingerprint_protection = request_data.get('preferences', {}).get('fingerprint_protection', True)
            
            # For high-risk sites, force fingerprint protection
            if policy_result['risk_level'] in ['high', 'critical'] and not use_fingerprint_protection:
                use_fingerprint_protection = True
                logger.info(f"[{request_id}] Forcing fingerprint protection due to high risk")
            
            execution_start = datetime.now()
            
            if use_fingerprint_protection:
                # Use browser-based protection (slower but more secure)
                logger.info(f"[{request_id}] Using fingerprint-protected request via {proxy_config['type']}")
                response_data = self.fingerprint_manager.make_protected_request(
                    url=target_url,
                    proxy_config=proxy_config,
                    method=request_data.get('method', 'GET'),
                    data=request_data.get('data'),
                    headers=request_data.get('headers')
                )
            else:
                # Use direct requests (faster but less protection)
                logger.info(f"[{request_id}] Using direct request via {proxy_config['type']}")
                response_data = self._make_direct_request(
                    url=target_url,
                    proxy_config=proxy_config,
                    method=request_data.get('method', 'GET'),
                    data=request_data.get('data'),
                    headers=request_data.get('headers')
                )
            
            execution_time = (datetime.now() - execution_start).total_seconds()
            
            # Step 4: Compile Results
            request_end_time = datetime.now()
            total_time = (request_end_time - request_start_time).total_seconds()
            
            # Determine risk level for response
            risk_level = policy_result.get('risk_level', 'medium')
            
            # Log the request
            self._log_request(
                request_id=request_id,
                user_id=user_id,
                request_data=request_data,
                policy_result=policy_result,
                proxy_config=proxy_config,
                response_data=response_data,
                total_time=total_time,
                policy_time=policy_time,
                execution_time=execution_time,
                risk_level=risk_level
            )
            
            # Update user statistics
            self._update_stats(
                user_id=user_id,
                success=response_data.get('success', False),
                backend=proxy_config['type'],
                response_time=total_time
            )
            
            return {
                'success': response_data.get('success', False),
                'request_id': request_id,
                'response': {
                    'status_code': response_data.get('status_code'),
                    'content': response_data.get('content'),
                    'content_length': response_data.get('content_length'),
                    'headers': response_data.get('headers', {}),
                    'final_url': response_data.get('final_url'),
                    'response_time': response_data.get('response_time') or response_data.get('load_time')
                },
                'policy_metadata': {
                    'allowed': policy_result['allowed'],
                    'reason': policy_result['reason'],
                    'risk_score': policy_result.get('risk_score', 0),
                    'risk_level': risk_level,
                    'suggested_backend': policy_result.get('suggested_backend', 'auto'),
                    'risk_factors': policy_result.get('risk_factors', [])
                },
                'backend_used': proxy_config['type'],
                'target_domain': target_domain,
                'fingerprint_protection': use_fingerprint_protection,
                'performance': {
                    'policy_evaluation_time': policy_time,
                    'execution_time': execution_time,
                    'total_time': total_time
                },
                'timestamp': request_start_time.isoformat()
            }
            
        except Exception as e:
            logger.error(f"[{request_id}] Anonymity request processing failed: {str(e)}", exc_info=True)
            return {
                'success': False,
                'request_id': request_id,
                'error': f'Request processing failed: {str(e)}',
                'timestamp': request_start_time.isoformat()
            }
    
    def _make_fingerprint_protected_request(self, url, backend_type):
        """
        Make a request using Selenium with fingerprint protection.
        
        The FingerprintManager handles:
        - Browser automation with anti-detection measures
        - Proper proxy configuration for Tor
        - WebRTC leak prevention
        - User agent randomization
        
        Args:
            url: Target URL
            backend_type: Backend to use ('tor', 'direct')
        
        Returns:
            Response dictionary
        """
        logger.info(f"Fingerprint-protected request to {url} via {backend_type}")
        
        try:
            result = self.fingerprint_manager.fetch_page(
                url=url,
                backend_type=backend_type,
                timeout=90  # Tor can be slow
            )
            return result
            
        except Exception as e:
            logger.error(f"Fingerprint-protected request failed: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'error_type': 'FINGERPRINT_REQUEST_ERROR'
            }
    
    def _make_direct_request(self, url: str, proxy_config: Dict[str, Any],
                               method: str = 'GET', data: Dict = None,
                               headers: Dict = None) -> Dict[str, Any]:
        """
        Make a request using the requests library (no fingerprint protection).
        
        This is faster but provides less anonymity protection.
        
        Args:
            url: Target URL
            proxy_config: Proxy configuration from ProxyManager
            method: HTTP method
            data: Request body data
            headers: Custom headers
        
        Returns:
            Response dictionary
        """
        backend_type = proxy_config.get('type', 'direct')
        logger.info(f"Direct request to {url} via {backend_type}")
        
        try:
            # Configure proxy based on backend
            proxies = None
            if backend_type == 'tor':
                proxies = self.tor_proxy
                logger.debug(f"Using Tor proxy: {proxies}")
            
            # Request headers
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'max-age=0'
            }
            
            # Make the request
            response = requests.get(
                url,
                proxies=proxies,
                headers=headers,
                timeout=60,
                verify=True,
                allow_redirects=True
            )
            
            return {
                'success': True,
                'content': response.text,
                'content_length': len(response.text),
                'status_code': response.status_code,
                'final_url': response.url,
                'headers': dict(response.headers),
                'title': self._extract_title(response.text)
            }
            
        except requests.exceptions.ProxyError as e:
            logger.error(f"Proxy error: {e}")
            return {
                'success': False,
                'error': f'Tor proxy error. Is Tor running on port 9050?',
                'error_type': 'PROXY_ERROR'
            }
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error: {e}")
            return {
                'success': False,
                'error': f'Connection failed. The website may be unreachable.',
                'error_type': 'CONNECTION_ERROR'
            }
        except requests.exceptions.Timeout as e:
            logger.error(f"Timeout: {e}")
            return {
                'success': False,
                'error': f'Request timed out.',
                'error_type': 'TIMEOUT'
            }
        except Exception as e:
            logger.error(f"Request error: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'error_type': 'UNKNOWN'
            }
    
    def _extract_domain(self, url):
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc
        except:
            return url
    
    def _extract_title(self, html_content):
        """Extract title from HTML content"""
        try:
            import re
            match = re.search(r'<title[^>]*>([^<]+)</title>', html_content, re.IGNORECASE)
            if match:
                return match.group(1).strip()
            return None
        except:
            return None
    
    def verify_tor_connection(self) -> Dict[str, Any]:
        """
        Verify Tor connection using requests library (no fingerprint protection)
        """
        return self._check_tor_connectivity()
    
    def verify_tor_with_fingerprint_protection(self) -> Dict[str, Any]:
        """
        Verify Tor connection using Selenium with fingerprint protection
        """
        try:
            result = self.fingerprint_manager.test_tor_connection()
            return result
        except Exception as e:
            logger.error(f"Tor verification with fingerprint protection failed: {e}")
            return {
                'tor_working': False,
                'error': str(e)
            }
