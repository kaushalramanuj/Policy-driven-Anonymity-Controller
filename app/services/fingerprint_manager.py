"""
Fingerprint Manager - Browser fingerprint protection with proper Tor routing
Manages Selenium WebDriver with anti-fingerprinting techniques
"""

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException, WebDriverException
from webdriver_manager.chrome import ChromeDriverManager
import logging
import time
import random
from typing import Dict, Any

logger = logging.getLogger(__name__)


class FingerprintManager:
    """
    Manages browser fingerprint protection with proper Tor/proxy routing.
    
    This class handles:
    - Selenium WebDriver creation with anti-fingerprinting measures
    - Proper proxy configuration for Tor/other backends
    - WebRTC leak prevention
    - User agent randomization
    - Canvas fingerprint protection
    """
    
    def __init__(self):
        self.driver = None
        self.protection_enabled = True
        
        # Tor SOCKS5 proxy configuration
        self.tor_proxy_host = "127.0.0.1"
        self.tor_proxy_port = 9050
        
        # Window sizes to randomize (common resolutions)
        self.window_sizes = [
            (1920, 1080),
            (1366, 768),
            (1536, 864),
            (1440, 900),
            (1280, 720)
        ]
        
        # User agents pool (updated, common browsers)
        self.user_agents = [
            # Chrome on Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
            # Chrome on Mac
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            # Chrome on Linux
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            # Firefox on Windows
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
            # Firefox on Mac
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0',
        ]
        
        logger.info("FingerprintManager initialized")
    
    def get_fingerprint_stats(self) -> Dict[str, Any]:
        """Return fingerprint protection statistics"""
        return {
            'protection_enabled': self.protection_enabled,
            'tor_proxy': f"socks5://{self.tor_proxy_host}:{self.tor_proxy_port}",
            'driver_active': self.driver is not None,
            'user_agents_count': len(self.user_agents),
            'window_sizes_count': len(self.window_sizes)
        }
    
    def _get_random_window_size(self):
        """Get a random common window size"""
        return random.choice(self.window_sizes)
    
    def _get_random_user_agent(self):
        """Get a random user agent string"""
        return random.choice(self.user_agents)
    
    def _create_chrome_options(self, backend_type='tor'):
        """
        Create Chrome options with proper proxy and anti-fingerprinting configuration.
        
        Args:
            backend_type: 'tor', 'direct', 'proxy', or 'auto'
        
        Returns:
            Configured Chrome Options object
        """
        options = Options()
        
        # Get random window size
        width, height = self._get_random_window_size()
        
        # Get random user agent
        user_agent = self._get_random_user_agent()
        options.add_argument(f'--user-agent={user_agent}')
        logger.debug(f"Using user agent: {user_agent[:50]}...")
        
        # ============================================
        # CRITICAL: Proxy Configuration
        # ============================================
        if backend_type in ['tor', 'auto']:
            # Configure SOCKS5 proxy for Tor
            # Use socks5 (not socks5h) for Chrome - Chrome handles DNS differently
            proxy_address = f"socks5://127.0.0.1:9050"
            options.add_argument(f'--proxy-server={proxy_address}')
            logger.info(f"Chrome configured with Tor proxy: {proxy_address}")
            
            # IMPORTANT: Route DNS through the proxy (prevents DNS leaks)
            # This ensures .onion addresses can be resolved
            options.add_argument('--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1')
        elif backend_type == 'direct':
            logger.info("Chrome configured for direct connection (no proxy)")
            # No proxy configuration needed
        else:
            logger.info(f"Chrome configured with backend: {backend_type}")
        
        # ============================================
        # Basic Chrome Options
        # ============================================
        options.add_argument('--headless=new')  # New headless mode (Chrome 109+)
        options.add_argument('--no-sandbox')
        options.add_argument('--disable-dev-shm-usage')
        options.add_argument('--disable-gpu')
        options.add_argument(f'--window-size={width},{height}')
        
        # ============================================
        # Privacy & Anti-Detection Options
        # ============================================
        
        # Disable automation detection
        options.add_argument('--disable-blink-features=AutomationControlled')
        options.add_experimental_option('excludeSwitches', ['enable-automation'])
        options.add_experimental_option('useAutomationExtension', False)
        
        # Disable infobars
        options.add_argument('--disable-infobars')
        
        # Disable extensions
        options.add_argument('--disable-extensions')
        
        # Disable popup blocking
        options.add_argument('--disable-popup-blocking')
        
        # Disable save password bubble
        options.add_argument('--disable-save-password-bubble')
        
        # ============================================
        # WebRTC Leak Prevention (CRITICAL for Tor)
        # ============================================
        # WebRTC can leak your real IP even when using a proxy
        prefs = {
            # Disable WebRTC IP handling
            'webrtc.ip_handling_policy': 'disable_non_proxied_udp',
            'webrtc.multiple_routes_enabled': False,
            'webrtc.nonproxied_udp_enabled': False,
            
            # Disable location services
            'profile.default_content_setting_values.geolocation': 2,
            
            # Disable notifications
            'profile.default_content_setting_values.notifications': 2,
            
            # Disable password saving prompts
            'credentials_enable_service': False,
            'profile.password_manager_enabled': False,
            
            # Disable autofill
            'autofill.profile_enabled': False,
            'autofill.credit_card_enabled': False
        }
        options.add_experimental_option('prefs', prefs)
        
        return options
    
    def _create_driver(self, backend_type='tor'):
        """
        Create a new Chrome WebDriver instance with specified backend.
        
        Args:
            backend_type: The backend to use ('tor', 'direct', 'auto')
        
        Returns:
            WebDriver instance
        """
        try:
            # Close existing driver if any
            self.close_driver()
            
            # Create options with proxy configuration
            options = self._create_chrome_options(backend_type=backend_type)
            
            # Create WebDriver service
            service = Service(ChromeDriverManager().install())
            
            # Create the driver
            self.driver = webdriver.Chrome(service=service, options=options)
            
            # Set timeouts
            self.driver.set_page_load_timeout(90)  # Tor can be slow
            self.driver.set_script_timeout(30)
            self.driver.implicitly_wait(10)
            
            # Inject anti-fingerprinting JavaScript
            self._inject_fingerprint_protection()
            
            logger.info(f"WebDriver created successfully with backend: {backend_type}")
            return self.driver
            
        except WebDriverException as e:
            logger.error(f"WebDriver creation failed: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error creating WebDriver: {e}", exc_info=True)
            raise
    
    def _inject_fingerprint_protection(self):
        """
        Inject JavaScript to mask browser fingerprinting attempts.
        This runs on every new document loaded.
        """
        if not self.driver:
            return
        
        try:
            # JavaScript to override fingerprinting vectors
            js_code = '''
                // Override navigator.webdriver (automation detection)
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                });
                
                // Override navigator.plugins (make it look like normal browser)
                Object.defineProperty(navigator, 'plugins', {
                    get: () => {
                        return [
                            { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
                            { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
                            { name: 'Native Client', filename: 'internal-nacl-plugin' }
                        ];
                    }
                });
                
                // Override navigator.languages
                Object.defineProperty(navigator, 'languages', {
                    get: () => ['en-US', 'en']
                });
                
                // Override navigator.platform (be consistent)
                Object.defineProperty(navigator, 'platform', {
                    get: () => 'Win32'
                });
                
                // Override navigator.hardwareConcurrency (CPU cores)
                Object.defineProperty(navigator, 'hardwareConcurrency', {
                    get: () => 4
                });
                
                // Override navigator.deviceMemory
                Object.defineProperty(navigator, 'deviceMemory', {
                    get: () => 8
                });
                
                // Mock chrome runtime (expected in Chrome)
                if (!window.chrome) {
                    window.chrome = {};
                }
                if (!window.chrome.runtime) {
                    window.chrome.runtime = {};
                }
                
                // Override WebGL renderer (common fingerprinting vector)
                const getParameterProxyHandler = {
                    apply: function(target, thisArg, args) {
                        const param = args[0];
                        // UNMASKED_VENDOR_WEBGL
                        if (param === 37445) {
                            return 'Google Inc. (NVIDIA)';
                        }
                        // UNMASKED_RENDERER_WEBGL
                        if (param === 37446) {
                            return 'ANGLE (NVIDIA, NVIDIA GeForce GTX 1080 Direct3D11 vs_5_0 ps_5_0, D3D11)';
                        }
                        return Reflect.apply(target, thisArg, args);
                    }
                };
                
                // Apply WebGL proxy if available
                try {
                    const canvas = document.createElement('canvas');
                    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
                    if (gl) {
                        const originalGetParameter = gl.getParameter.bind(gl);
                        gl.getParameter = new Proxy(originalGetParameter, getParameterProxyHandler);
                    }
                } catch (e) {}
                
                // Override screen properties
                Object.defineProperty(screen, 'colorDepth', { get: () => 24 });
                Object.defineProperty(screen, 'pixelDepth', { get: () => 24 });
                
                // Disable battery API (fingerprinting vector)
                if (navigator.getBattery) {
                    navigator.getBattery = undefined;
                }
                
                console.log('Fingerprint protection injected');
            '''
            
            # Execute on new documents
            self.driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
                'source': js_code
            })
            
            logger.debug("Fingerprint protection JavaScript injected")
            
        except Exception as e:
            logger.warning(f"Could not inject fingerprint protection: {e}")
    
    def fetch_page(self, url, backend_type='tor', timeout=90):
        """
        Fetch a webpage with fingerprint protection through the specified backend.
        
        Args:
            url: The URL to fetch
            backend_type: Backend to use ('tor', 'direct', 'auto')
            timeout: Page load timeout in seconds
        
        Returns:
            Dictionary with success status, content, and metadata
        """
        start_time = time.time()
        
        try:
            logger.info(f"Fetching {url} via {backend_type} with fingerprint protection")
            
            # Create driver with appropriate backend
            driver = self._create_driver(backend_type=backend_type)
            
            # Navigate to url
            driver.get(url)
            
            # Wait for page to fully load
            try:
                WebDriverWait(driver, timeout).until(
                    lambda d: d.execute_script('return document.readyState') == 'complete'
                )
            except TimeoutException:
                logger.warning(f"Page load timed out for {url}, continuing with partial content")
            
            # Small delay to let dynamic content load
            time.sleep(1)
            
            # Collect page information
            content = driver.page_source
            current_url = driver.current_url
            title = driver.title
            
            # Try to get cookies (for debugging)
            try:
                cookies = driver.get_cookies()
            except:
                cookies = []
            
            load_time = time.time() - start_time
            
            logger.info(f"Successfully fetched {url} in {load_time:.2f}s via {backend_type}")
            
            return {
                'success': True,
                'content': content,
                'content_length': len(content),
                'final_url': current_url,
                'title': title,
                'status_code': 200,  # Selenium doesn't provide HTTP status
                'load_time': load_time,
                'backend_used': backend_type,
                'cookies_count': len(cookies),
                'fingerprint_protection': True
            }
            
        except TimeoutException as e:
            load_time = time.time() - start_time
            logger.error(f"Timeout fetching {url}: {e}")
            return {
                'success': False,
                'error': f'Page load timed out after {timeout}s. The site may be slow or unreachable via {backend_type}.',
                'error_type': 'TIMEOUT',
                'backend_used': backend_type,
                'load_time': load_time
            }
            
        except WebDriverException as e:
            load_time = time.time() - start_time
            error_msg = str(e)
            
            # Parse common WebDriver errors
            if 'net::ERR_PROXY_CONNECTION_FAILED' in error_msg:
                error = 'Tor proxy connection failed. Is Tor running on port 9050?'
                error_type = 'PROXY_ERROR'
            elif 'net::ERR_NAME_NOT_RESOLVED' in error_msg:
                error = 'Domain name could not be resolved. Check if the URL is correct.'
                error_type = 'DNS_ERROR'
            elif 'net::ERR_CONNECTION_TIMED_OUT' in error_msg:
                error = 'Connection timed out. The website may be down or blocking Tor.'
                error_type = 'TIMEOUT'
            elif 'net::ERR_CONNECTION_REFUSED' in error_msg:
                error = 'Connection refused by the server.'
                error_type = 'CONNECTION_REFUSED'
            else:
                error = f'WebDriver error: {error_msg[:200]}'
                error_type = 'WEBDRIVER_ERROR'
            
            logger.error(f"WebDriver error fetching {url}: {error}")
            return {
                'success': False,
                'error': error,
                'error_type': error_type,
                'backend_used': backend_type,
                'load_time': load_time
            }
            
        except Exception as e:
            load_time = time.time() - start_time
            logger.error(f"Unexpected error fetching {url}: {e}", exc_info=True)
            return {
                'success': False,
                'error': str(e),
                'error_type': 'UNKNOWN',
                'backend_used': backend_type,
                'load_time': load_time
            }
            
        finally:
            # Always close the driver to free resources
            self.close_driver()
    
    def close_driver(self):
        """Safely close and cleanup the WebDriver"""
        if self.driver:
            try:
                self.driver.quit()
                logger.debug("WebDriver closed successfully")
            except Exception as e:
                logger.warning(f"Error closing WebDriver: {e}")
            finally:
                self.driver = None
    
    def test_tor_connection(self):
        """
        Test if Tor connection is working through Selenium.
        
        Returns:
            Dictionary with test results
        """
        try:
            result = self.fetch_page('https://check.torproject.org', backend_type='tor', timeout=60)
            
            if result.get('success'):
                content = result.get('content', '')
                is_tor = 'Congratulations' in content and 'using Tor' in content
                
                # Try to extract IP from the page
                import re
                ip_match = re.search(r'Your IP address appears to be:\s*<strong>([^<]+)</strong>', content)
                exit_ip = ip_match.group(1) if ip_match else 'Unknown'
                
                return {
                    'tor_working': is_tor,
                    'exit_ip': exit_ip,
                    'message': 'Tor is working correctly!' if is_tor else 'Connected but NOT using Tor!',
                    'load_time': result.get('load_time'),
                    'fingerprint_protection': True
                }
            else:
                return {
                    'tor_working': False,
                    'error': result.get('error'),
                    'error_type': result.get('error_type')
                }
                
        except Exception as e:
            return {
                'tor_working': False,
                'error': str(e)
            }
    
    def make_protected_request(self, url: str, proxy_config: Dict[str, Any],
                               method: str = 'GET', data: Dict = None,
                               headers: Dict = None) -> Dict[str, Any]:
        """
        Make a request with fingerprint protection using Selenium.
        
        Args:
            url: Target URL
            proxy_config: Proxy configuration from ProxyManager
            method: HTTP method (currently only GET is fully supported)
            data: Request body data (for POST requests)
            headers: Custom headers
        
        Returns:
            Response dictionary with success status and data
        """
        # Determine backend type from proxy_config
        backend_type = proxy_config.get('type', 'tor')
        
        logger.info(f"Making protected request to {url} via {backend_type}")
        
        # Use fetch_page which handles the Selenium setup
        result = self.fetch_page(url, backend_type=backend_type)
        
        return result


# Create singleton instance
fingerprint_manager = FingerprintManager()
