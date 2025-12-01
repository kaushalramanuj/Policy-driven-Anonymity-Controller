"""
Request Log Model - Enhanced with validation utilities
Tracks all anonymity requests for monitoring and analytics
"""
from app.extensions import db
from app.utils.validators import URLValidator, InputValidator
from app.utils.security import SecurityUtils
from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)


class RequestLog(db.Model):
    """
    Request log model with enhanced validation and security
    """
    __tablename__ = 'request_logs'

    # Primary Key
    id = db.Column(db.Integer, primary_key=True)
    request_id = db.Column(db.String(64), unique=True, index=True)  # Unique request identifier

    # User Association
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    session_id = db.Column(db.String(100), index=True)  # For anonymous users

    # Request Details
    target_url = db.Column(db.Text, nullable=False)
    target_domain = db.Column(db.String(255), index=True)  # Extracted domain for faster queries
    method = db.Column(db.String(10), default='GET', index=True)
    request_headers = db.Column(db.Text)  # JSON string
    request_data = db.Column(db.Text)  # JSON string

    # Backend Information
    backend_used = db.Column(db.String(20), index=True)  # direct, http, https, tor
    proxy_address = db.Column(db.String(255))
    fingerprint_protection_enabled = db.Column(db.Boolean, default=False, index=True)

    # Response Information
    success = db.Column(db.Boolean, default=False, index=True)
    status_code = db.Column(db.Integer)
    response_size = db.Column(db.Integer)  # in bytes
    error_message = db.Column(db.Text)

    # Performance Metrics
    response_time = db.Column(db.Float)  # in seconds
    policy_evaluation_time = db.Column(db.Float)  # in seconds
    total_time = db.Column(db.Float, index=True)  # in seconds

    # Policy Information
    policy_allowed = db.Column(db.Boolean, default=True, index=True)
    policy_reason = db.Column(db.Text)
    risk_score = db.Column(db.Float, index=True)
    risk_level = db.Column(db.String(20), index=True)  # low, medium, high, critical

    # Request Context
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.Text)
    referrer = db.Column(db.Text)

    # Timestamps
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Flags
    flagged = db.Column(db.Boolean, default=False, index=True)
    flagged_reason = db.Column(db.Text)
    reviewed = db.Column(db.Boolean, default=False)

    def __init__(self, **kwargs):
        """
        Initialize request log with validation

        Args:
            **kwargs: Request log attributes
        """
        # Generate unique request ID
        self.request_id = SecurityUtils.generate_secure_token(32)

        # Validate and set target URL
        target_url = kwargs.get('target_url')
        if target_url:
            is_valid, msg = URLValidator.is_valid_url(target_url)
            if not is_valid:
                logger.warning(f"Invalid URL in request log: {target_url}")

            self.target_url = target_url
            self.target_domain = URLValidator.extract_domain(target_url) or 'unknown'

        # Validate and sanitize session ID
        session_id = kwargs.get('session_id')
        if session_id:
            if InputValidator.is_valid_session_id(session_id):
                self.session_id = session_id
            else:
                logger.warning(f"Invalid session ID in request log")
                self.session_id = 'invalid'

        # Set other attributes
        for key, value in kwargs.items():
            if key not in ['target_url', 'session_id'] and hasattr(self, key):
                setattr(self, key, value)

        # Auto-flag suspicious requests
        self._check_and_flag_suspicious()

    def _check_and_flag_suspicious(self):
        """Automatically flag suspicious requests"""
        reasons = []

        # High risk score
        if self.risk_score and self.risk_score > 0.8:
            reasons.append("High risk score")

        # Failed request
        if not self.success and self.policy_allowed:
            reasons.append("Request failed after policy approval")

        # Very slow response
        if self.total_time and self.total_time > 30:
            reasons.append("Extremely slow response time")

        # Suspicious user agent
        if self.user_agent:
            suspicious_patterns = ['bot', 'crawler', 'scanner', 'curl']
            if any(pattern in self.user_agent.lower() for pattern in suspicious_patterns):
                reasons.append("Suspicious user agent detected")

        if reasons:
            self.flagged = True
            self.flagged_reason = '; '.join(reasons)
            logger.info(f"Request {self.request_id} flagged: {self.flagged_reason}")

    def set_request_headers(self, headers: dict):
        """
        Set request headers with validation

        Args:
            headers: Dictionary of HTTP headers
        """
        from app.utils.validators import RequestValidator

        is_valid, msg = RequestValidator.validate_headers(headers)
        if not is_valid:
            logger.warning(f"Invalid headers in request log: {msg}")
            headers = {}

        self.request_headers = json.dumps(headers)

    def get_request_headers(self):
        """Get request headers as dictionary"""
        if not self.request_headers:
            return {}

        try:
            return json.loads(self.request_headers)
        except json.JSONDecodeError:
            logger.error(f"Failed to parse request headers for log {self.id}")
            return {}

    def set_request_data(self, data: dict):
        """Set request data as JSON string"""
        if data:
            self.request_data = json.dumps(data)

    def get_request_data(self):
        """Get request data as dictionary"""
        if not self.request_data:
            return None

        try:
            return json.loads(self.request_data)
        except json.JSONDecodeError:
            logger.error(f"Failed to parse request data for log {self.id}")
            return None

    def to_dict(self, include_sensitive=False):
        """
        Convert request log to dictionary

        Args:
            include_sensitive: Whether to include sensitive information

        Returns:
            Dictionary representation
        """
        log_dict = {
            'id': self.id,
            'request_id': self.request_id,
            'user_id': self.user_id,
            'session_id': self.session_id[:8] + '...' if self.session_id and not include_sensitive else self.session_id,
            'target_domain': self.target_domain,
            'method': self.method,
            'backend_used': self.backend_used,
            'success': self.success,
            'status_code': self.status_code,
            'response_time': round(self.response_time, 3) if self.response_time else None,
            'total_time': round(self.total_time, 3) if self.total_time else None,
            'policy_allowed': self.policy_allowed,
            'risk_score': round(self.risk_score, 3) if self.risk_score else None,
            'risk_level': self.risk_level,
            'fingerprint_protection_enabled': self.fingerprint_protection_enabled,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'flagged': self.flagged,
            'flagged_reason': self.flagged_reason if self.flagged else None
        }

        if include_sensitive:
            log_dict['target_url'] = self.target_url
            log_dict['ip_address'] = self.ip_address
            log_dict['user_agent'] = self.user_agent
            log_dict['error_message'] = self.error_message
            log_dict['policy_reason'] = self.policy_reason

        return log_dict

    @classmethod
    def get_statistics(cls, user_id=None, days=7):
        """
        Get request statistics with enhanced metrics

        Args:
            user_id: Optional user ID to filter by
            days: Number of days to look back

        Returns:
            Dictionary with comprehensive statistics
        """
        from datetime import timedelta

        cutoff_date = datetime.utcnow() - timedelta(days=days)
        query = cls.query.filter(cls.timestamp >= cutoff_date)

        if user_id:
            query = query.filter(cls.user_id == user_id)

        logs = query.all()

        if not logs:
            return {
                'total_requests': 0,
                'successful_requests': 0,
                'failed_requests': 0,
                'success_rate': 0,
                'average_response_time': 0,
                'backend_distribution': {},
                'risk_distribution': {},
                'flagged_count': 0,
                'period_days': days
            }

        total = len(logs)
        successful = sum(1 for log in logs if log.success)
        failed = total - successful
        flagged = sum(1 for log in logs if log.flagged)

        # Calculate averages
        total_response_time = sum(log.response_time or 0 for log in logs)
        avg_response_time = total_response_time / total if total > 0 else 0

        # Backend distribution
        backend_dist = {}
        for log in logs:
            backend = log.backend_used or 'unknown'
            backend_dist[backend] = backend_dist.get(backend, 0) + 1

        # Risk distribution
        risk_dist = {}
        for log in logs:
            risk = log.risk_level or 'unknown'
            risk_dist[risk] = risk_dist.get(risk, 0) + 1

        # Top domains
        domain_dist = {}
        for log in logs:
            domain = log.target_domain or 'unknown'
            domain_dist[domain] = domain_dist.get(domain, 0) + 1

        top_domains = sorted(domain_dist.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            'total_requests': total,
            'successful_requests': successful,
            'failed_requests': failed,
            'success_rate': round((successful / total * 100), 2) if total > 0 else 0,
            'average_response_time': round(avg_response_time, 3),
            'backend_distribution': backend_dist,
            'risk_distribution': risk_dist,
            'flagged_count': flagged,
            'flagged_percentage': round((flagged / total * 100), 2) if total > 0 else 0,
            'top_domains': top_domains,
            'period_days': days,
            'first_request': logs[0].timestamp.isoformat() if logs else None,
            'last_request': logs[-1].timestamp.isoformat() if logs else None
        }

    def __repr__(self):
        return f'<RequestLog {self.request_id}: {self.method} {self.target_domain}>'
