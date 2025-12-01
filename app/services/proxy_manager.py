"""
Proxy Manager - Manages proxy configurations for different backends
Handles Tor, VPN, and direct connections
"""

import logging
import time
import requests
from datetime import datetime

logger = logging.getLogger(__name__)


class ProxyManager:
    """
    Manages proxy configurations and connections for various backends.
    
    Supported backends:
    - Tor (SOCKS5 proxy on port 9050)
    - Direct (no proxy)
    - VPN (if configured)
    - Custom proxy
    """
    
    def __init__(self):
        # Tor configuration
        self.tor_host = "127.0.0.1"
        self.tor_port = 9050
        self.tor_control_port = 9051
        
        # Proxy configurations
        self.proxies = {
            'tor': {
                'http': f'socks5h://{self.tor_host}:{self.tor_port}',
                'https': f'socks5h://{self.tor_host}:{self.tor_port}'
            },
            'direct': None,
            'vpn': None  # Configure if VPN is available
        }
        
        # Connection status cache
        self._status_cache = {
            'tor': {'working': None, 'last_check': None, 'response_time': None},
            'direct': {'working': None, 'last_check': None, 'response_time': None}
        }
        
        # Test URL for connectivity checks
        self.test_url = 'https://check.torproject.org/api/ip'
        self.direct_test_url = 'https://httpbin.org/ip'
        
        logger.info("ProxyManager initialized")
    
    def get_status(self):
        """
        Get current status of all proxy backends.
        
        Returns:
            Dictionary with proxy status information
        """
        # Check Tor status
        tor_status = self._check_tor_status()
        
        # Check direct connection status
        direct_status = self._check_direct_status()
        
        return {
            'active': True,
            'backends': {
                'tor': {
                    'configured': True,
                    'host': self.tor_host,
                    'port': self.tor_port,
                    'working': tor_status.get('working', False),
                    'last_check': tor_status.get('last_check'),
                    'response_time': tor_status.get('response_time'),
                    'exit_ip': tor_status.get('exit_ip')
                },
                'direct': {
                    'configured': True,
                    'working': direct_status.get('working', False),
                    'last_check': direct_status.get('last_check'),
                    'response_time': direct_status.get('response_time'),
                    'ip': direct_status.get('ip')
                },
                'vpn': {
                    'configured': False,
                    'working': False
                }
            },
            'default_backend': 'tor',
            'timestamp': datetime.now().isoformat()
        }
    
    def _check_tor_status(self):
        """Check if Tor connection is working"""
        try:
            # Use cached result if recent (within 30 seconds)
            cache = self._status_cache.get('tor', {})
            if cache.get('last_check'):
                cache_age = (datetime.now() - datetime.fromisoformat(cache['last_check'])).total_seconds()
                if cache_age < 30 and cache.get('working') is not None:
                    return cache
            
            # Perform actual check
            start_time = time.time()
            response = requests.get(
                self.test_url,
                proxies=self.proxies['tor'],
                timeout=15
            )
            response_time = time.time() - start_time
            
            data = response.json()
            is_tor = data.get('IsTor', False)
            exit_ip = data.get('IP', 'Unknown')
            
            # Update cache
            self._status_cache['tor'] = {
                'working': is_tor,
                'last_check': datetime.now().isoformat(),
                'response_time': round(response_time, 2),
                'exit_ip': exit_ip
            }
            
            return self._status_cache['tor']
            
        except Exception as e:
            logger.debug(f"Tor status check failed: {e}")
            self._status_cache['tor'] = {
                'working': False,
                'last_check': datetime.now().isoformat(),
                'response_time': None,
                'error': str(e)
            }
            return self._status_cache['tor']
    
    def _check_direct_status(self):
        """Check if direct connection is working"""
        try:
            # Use cached result if recent (within 60 seconds)
            cache = self._status_cache.get('direct', {})
            if cache.get('last_check'):
                cache_age = (datetime.now() - datetime.fromisoformat(cache['last_check'])).total_seconds()
                if cache_age < 60 and cache.get('working') is not None:
                    return cache
            
            # Perform actual check
            start_time = time.time()
            response = requests.get(
                self.direct_test_url,
                timeout=10
            )
            response_time = time.time() - start_time
            
            data = response.json()
            ip = data.get('origin', 'Unknown')
            
            # Update cache
            self._status_cache['direct'] = {
                'working': True,
                'last_check': datetime.now().isoformat(),
                'response_time': round(response_time, 2),
                'ip': ip
            }
            
            return self._status_cache['direct']
            
        except Exception as e:
            logger.debug(f"Direct status check failed: {e}")
            self._status_cache['direct'] = {
                'working': False,
                'last_check': datetime.now().isoformat(),
                'response_time': None,
                'error': str(e)
            }
            return self._status_cache['direct']
    
    def get_optimal_proxy(self, backend_type='auto'):
        """
        Get the optimal proxy configuration based on backend type.
        
        Args:
            backend_type: 'tor', 'direct', 'vpn', or 'auto'
        
        Returns:
            Dictionary with proxy configuration
        """
        if backend_type == 'auto':
            # Check if Tor is available, otherwise use direct
            tor_status = self._check_tor_status()
            if tor_status.get('working'):
                backend_type = 'tor'
            else:
                backend_type = 'direct'
                logger.warning("Tor not available, falling back to direct connection")
        
        proxy_config = {
            'type': backend_type,
            'proxy': self.proxies.get(backend_type),
            'metadata': {}
        }
        
        if backend_type == 'tor':
            proxy_config['metadata'] = {
                'host': self.tor_host,
                'port': self.tor_port,
                'protocol': 'socks5h'
            }
        
        return proxy_config
    
    def _get_tor_proxy(self):
        """Get Tor SOCKS5 proxy configuration"""
        return self.proxies['tor']
    
    def test_proxy_connection(self, proxy_config):
        """
        Test if a proxy connection is working.
        
        Args:
            proxy_config: Dictionary with proxy configuration
        
        Returns:
            Tuple of (is_working: bool, response_time: float)
        """
        try:
            backend_type = proxy_config.get('type', 'direct')
            proxies = proxy_config.get('proxy')
            
            # Choose test URL based on backend
            if backend_type == 'tor':
                test_url = self.test_url
            else:
                test_url = self.direct_test_url
            
            start_time = time.time()
            response = requests.get(
                test_url,
                proxies=proxies,
                timeout=20
            )
            response_time = time.time() - start_time
            
            # For Tor, verify we're actually using Tor
            if backend_type == 'tor':
                data = response.json()
                is_working = data.get('IsTor', False)
            else:
                is_working = response.status_code == 200
            
            return is_working, round(response_time, 2)
            
        except Exception as e:
            logger.error(f"Proxy connection test failed: {e}")
            return False, 0.0
    
    def get_new_tor_circuit(self):
        """
        Request a new Tor circuit (requires Tor control port access).
        
        Returns:
            Boolean indicating success
        """
        try:
            # This requires the Tor control port to be accessible
            # and properly authenticated
            from stem import Signal
            from stem.control import Controller
            
            with Controller.from_port(port=self.tor_control_port) as controller:
                controller.authenticate()
                controller.signal(Signal.NEWNYM)
                logger.info("New Tor circuit requested")
                return True
                
        except ImportError:
            logger.warning("stem library not installed - cannot request new circuit")
            return False
        except Exception as e:
            logger.error(f"Failed to get new Tor circuit: {e}")
            return False
    
    def get_tor_exit_info(self):
        """
        Get information about the current Tor exit node.
        
        Returns:
            Dictionary with exit node information
        """
        try:
            response = requests.get(
                self.test_url,
                proxies=self.proxies['tor'],
                timeout=15
            )
            
            data = response.json()
            
            return {
                'is_tor': data.get('IsTor', False),
                'exit_ip': data.get('IP', 'Unknown'),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Failed to get Tor exit info: {e}")
            return {
                'is_tor': False,
                'error': str(e)
            }
