"""
Policy Engine - OPA/Rego-based policy evaluation for anonymity decisions
Queries OPA server for policy decisions using your anonymity.rego and user_attributes.json
"""

import logging
import time
import requests
import json
import os
from urllib.parse import urlparse
from datetime import datetime

logger = logging.getLogger(__name__)


class PolicyEngine:
    """
    Policy engine that queries OPA (Open Policy Agent) for policy decisions.
    Uses your anonymity.rego policy and user_attributes.json data.
    """
    
    def __init__(self):
        # OPA Configuration
        self.opa_url = os.getenv('OPA_URL', 'http://localhost:8181')
        self.opa_policy_endpoint = f"{self.opa_url}/v1/data/anonymity"
        self.opa_health_endpoint = f"{self.opa_url}/health"
        
        # Status tracking
        self.policies_loaded = False
        self.policy_count = 0
        self.last_evaluation_time = None
        self.total_evaluations = 0
        self.opa_available = False
        
        # Fallback risk thresholds (used if OPA is unavailable)
        self.risk_thresholds = {
            'low': 0.3,
            'medium': 0.6,
            'high': 0.8,
            'critical': 1.0
        }
        
        # Check OPA availability and load policy info
        self._check_opa_health()
        
        logger.info(f"PolicyEngine initialized (OPA: {self.opa_url}, Available: {self.opa_available})")
    
    def _check_opa_health(self):
        """Check if OPA server is available and policies are loaded"""
        try:
            response = requests.get(self.opa_health_endpoint, timeout=5)
            if response.status_code == 200:
                self.opa_available = True
                self.policies_loaded = True
                
                # Try to get policy count
                try:
                    policy_response = requests.get(f"{self.opa_url}/v1/policies", timeout=5)
                    if policy_response.status_code == 200:
                        policies = policy_response.json().get('result', [])
                        self.policy_count = len(policies)
                except:
                    self.policy_count = 1  # At least anonymity.rego
                
                logger.info(f"OPA is available with {self.policy_count} policies loaded")
            else:
                self.opa_available = False
                logger.warning(f"OPA health check failed: {response.status_code}")
                
        except requests.exceptions.ConnectionError:
            self.opa_available = False
            logger.warning("OPA server not available - will use fallback evaluation")
        except Exception as e:
            self.opa_available = False
            logger.error(f"OPA health check error: {e}")
    
    def get_status(self):
        """Get current status of the policy engine."""
        # Refresh OPA status
        self._check_opa_health()
        
        return {
            'active': True,
            'opa_available': self.opa_available,
            'opa_url': self.opa_url,
            'policies_loaded': self.policies_loaded,
            'policy_count': self.policy_count,
            'total_evaluations': self.total_evaluations,
            'last_evaluation': self.last_evaluation_time,
            'risk_thresholds': self.risk_thresholds
        }
    
    def check_health(self) -> bool:
        """Check if policy engine is healthy"""
        self._check_opa_health()
        return self.opa_available
    
    def evaluate_request(self, request_data):
        """
        Evaluate a request by querying OPA with your anonymity.rego policy.
        
        Args:
            request_data: Dictionary containing request details
        
        Returns:
            Dictionary with policy evaluation results
        """
        start_time = time.time()
        self.total_evaluations += 1
        
        # Get target URL from various possible keys
        target_url = (
            request_data.get('target_url') or 
            request_data.get('url') or 
            ''
        )
        
        # Try OPA first, fall back to local evaluation if unavailable
        if self.opa_available:
            result = self._evaluate_via_opa(target_url, request_data, start_time)
        else:
            logger.warning("OPA unavailable, using fallback evaluation")
            result = self._fallback_evaluate(target_url, start_time)
        
        self.last_evaluation_time = datetime.now().isoformat()
        
        return result
    
    def _evaluate_via_opa(self, target_url, request_data, start_time):
        """Query OPA for policy decision"""
        try:
            # Build OPA input matching your Rego policy structure
            opa_input = {
                "input": {
                    "request": {
                        "target_url": target_url,
                        "method": request_data.get('method', 'GET'),
                        "user_id": request_data.get('user_id', 'anonymous'),
                        "timestamp": datetime.now().isoformat()
                    },
                    "user": {
                        "session_id": request_data.get('user_id', 'anonymous'),
                        "preferences": request_data.get('preferences', {})
                    }
                }
            }
            
            logger.debug(f"Querying OPA with input: {json.dumps(opa_input, indent=2)}")
            
            # Query OPA
            response = requests.post(
                self.opa_policy_endpoint,
                json=opa_input,
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                opa_result = response.json().get('result', {})
                
                logger.info(f"OPA response: {json.dumps(opa_result, indent=2)}")
                
                # Extract values from OPA response
                risk_score = opa_result.get('risk_score', 0.5)
                risk_level = opa_result.get('risk_level', 'medium')
                suggested_backend = opa_result.get('suggested_backend', 'tor')
                reason = opa_result.get('reason', 'Policy evaluation completed')
                use_fingerprint = opa_result.get('use_fingerprint_protection', True)
                privacy_level = opa_result.get('privacy_level', 'moderate')
                
                evaluation_time = time.time() - start_time
                
                # Parse domain for logging
                try:
                    parsed = urlparse(target_url)
                    domain = parsed.netloc.lower()
                except:
                    domain = target_url
                
                result = {
                    'allowed': opa_result.get('allow', True),
                    'risk_score': round(risk_score, 3) if isinstance(risk_score, (int, float)) else 0.5,
                    'risk_level': risk_level,
                    'suggested_backend': suggested_backend,
                    'reason': reason,
                    'risk_factors': self._extract_risk_factors(opa_result, target_url),
                    'use_fingerprint_protection': use_fingerprint,
                    'privacy_level': privacy_level,
                    'evaluation_time': evaluation_time,
                    'policy_version': '1.0.0',
                    'domain_analyzed': domain,
                    'evaluation_source': 'opa'
                }
                
                logger.info(f"OPA evaluation for {domain}: risk={risk_level} ({risk_score}), backend={suggested_backend}")
                
                return result
                
            else:
                logger.error(f"OPA query failed with status {response.status_code}: {response.text}")
                return self._fallback_evaluate(target_url, start_time)
                
        except requests.exceptions.ConnectionError:
            logger.warning("OPA connection failed, using fallback")
            self.opa_available = False
            return self._fallback_evaluate(target_url, start_time)
            
        except Exception as e:
            logger.error(f"OPA evaluation error: {e}", exc_info=True)
            return self._fallback_evaluate(target_url, start_time)
    
    def _extract_risk_factors(self, opa_result, target_url):
        """Extract risk factors from OPA result and URL analysis"""
        factors = []
        
        risk_level = opa_result.get('risk_level', 'medium')
        risk_score = opa_result.get('risk_score', 0.5)
        
        if risk_level == 'low':
            factors.append("Safe domain detected by OPA policy")
        elif risk_level == 'high' or (isinstance(risk_score, (int, float)) and risk_score >= 0.8):
            factors.append("High-risk domain detected by OPA policy")
        elif risk_level == 'medium':
            factors.append("Unknown domain - elevated caution")
        
        # Check for specific patterns
        url_lower = target_url.lower()
        if '.onion' in url_lower:
            factors.append("Onion domain - requires Tor")
        
        if any(tld in url_lower for tld in ['.xyz', '.tk', '.ml', '.ga', '.cf']):
            factors.append("Suspicious TLD detected")
        
        return factors
    
    def _fallback_evaluate(self, target_url, start_time):
        """
        Fallback evaluation when OPA is unavailable.
        Uses conservative defaults - always suggests Tor for safety.
        """
        try:
            parsed = urlparse(target_url)
            domain = parsed.netloc.lower()
        except:
            domain = target_url
        
        # Conservative fallback - default to Tor for safety
        risk_score = 0.5
        risk_level = 'medium'
        suggested_backend = 'tor'
        reason = "OPA unavailable - using Tor for safety"
        
        # Check for obviously safe domains
        safe_domains = {
            'google.com', 'github.com', 'stackoverflow.com',
            'microsoft.com', 'wikipedia.org', 'python.org',
            'torproject.org', 'check.torproject.org', 'httpbin.org'
        }
        
        # Extract base domain
        parts = domain.split('.')
        if len(parts) >= 2:
            base_domain = '.'.join(parts[-2:])
        else:
            base_domain = domain
        
        if base_domain in safe_domains or domain in safe_domains:
            risk_score = 0.1
            risk_level = 'low'
            suggested_backend = 'direct'
            reason = f"Known safe domain: {base_domain} (fallback evaluation)"
        
        # Check for .onion
        if '.onion' in domain:
            risk_score = 0.8
            risk_level = 'high'
            suggested_backend = 'tor'
            reason = "Onion domain requires Tor"
        
        evaluation_time = time.time() - start_time
        
        return {
            'allowed': True,
            'risk_score': round(risk_score, 3),
            'risk_level': risk_level,
            'suggested_backend': suggested_backend,
            'reason': reason,
            'risk_factors': [reason],
            'use_fingerprint_protection': True,
            'privacy_level': 'moderate',
            'evaluation_time': evaluation_time,
            'policy_version': 'fallback',
            'domain_analyzed': domain,
            'evaluation_source': 'fallback'
        }
    
    def evaluate_anonymity_request(self, user_id: str, request_data: dict) -> dict:
        """Wrapper for compatibility with other components"""
        return self.evaluate_request(request_data)
    
    def get_policy_stats(self):
        """Get detailed policy statistics"""
        self._check_opa_health()
        
        return {
            'total_evaluations': self.total_evaluations,
            'policies_loaded': self.policies_loaded,
            'policy_count': self.policy_count,
            'last_evaluation': self.last_evaluation_time,
            'opa_available': self.opa_available,
            'opa_url': self.opa_url,
            'risk_thresholds': self.risk_thresholds
        }
