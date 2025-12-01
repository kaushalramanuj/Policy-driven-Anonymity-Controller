"""
Request Log Model for the Anonymity Controller
Tracks all anonymity requests for monitoring and analytics
"""
from app.extensions import db
from datetime import datetime


class RequestLog(db.Model):
    """
    Request log model for tracking anonymity requests
    """
    __tablename__ = 'request_logs'

    # Primary Key
    id = db.Column(db.Integer, primary_key=True)

    # User Association
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    session_id = db.Column(db.String(100), index=True)  # For anonymous users

    # Request Details
    target_url = db.Column(db.Text, nullable=False)
    method = db.Column(db.String(10), default='GET')
    request_headers = db.Column(db.Text)  # JSON string
    request_data = db.Column(db.Text)  # JSON string

    # Backend Information
    backend_used = db.Column(db.String(20))  # direct, http, https, tor
    proxy_address = db.Column(db.String(255))
    fingerprint_protection_enabled = db.Column(db.Boolean, default=False)

    # Response Information
    success = db.Column(db.Boolean, default=False)
    status_code = db.Column(db.Integer)
    response_size = db.Column(db.Integer)  # in bytes
    error_message = db.Column(db.Text)

    # Performance Metrics
    response_time = db.Column(db.Float)  # in seconds
    policy_evaluation_time = db.Column(db.Float)  # in seconds
    total_time = db.Column(db.Float)  # in seconds

    # Policy Information
    policy_allowed = db.Column(db.Boolean, default=True)
    policy_reason = db.Column(db.Text)
    risk_score = db.Column(db.Float)
    risk_level = db.Column(db.String(20))  # low, medium, high, critical

    # Request Context
    ip_address = db.Column(db.String(50))
    user_agent = db.Column(db.Text)
    referrer = db.Column(db.Text)

    # Timestamps
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Flags
    flagged = db.Column(db.Boolean, default=False)
    flagged_reason = db.Column(db.Text)
    reviewed = db.Column(db.Boolean, default=False)

    def __init__(self, **kwargs):
        """Initialize request log with provided data"""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def to_dict(self):
        """Convert request log to dictionary"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'target_url': self.target_url,
            'method': self.method,
            'backend_used': self.backend_used,
            'success': self.success,
            'status_code': self.status_code,
            'response_time': self.response_time,
            'total_time': self.total_time,
            'policy_allowed': self.policy_allowed,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'fingerprint_protection_enabled': self.fingerprint_protection_enabled,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'flagged': self.flagged
        }

    @classmethod
    def get_statistics(cls, user_id=None, days=7):
        """
        Get request statistics for a user or all users

        Args:
            user_id: Optional user ID to filter by
            days: Number of days to look back

        Returns:
            Dictionary with statistics
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
                'risk_distribution': {}
            }

        total = len(logs)
        successful = sum(1 for log in logs if log.success)
        failed = total - successful

        # Calculate averages
        avg_response_time = sum(log.response_time or 0 for log in logs) / total

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

        return {
            'total_requests': total,
            'successful_requests': successful,
            'failed_requests': failed,
            'success_rate': (successful / total * 100) if total > 0 else 0,
            'average_response_time': avg_response_time,
            'backend_distribution': backend_dist,
            'risk_distribution': risk_dist,
            'period_days': days
        }

    def __repr__(self):
        return f'<RequestLog {self.id}: {self.method} {self.target_url[:50]}>'
