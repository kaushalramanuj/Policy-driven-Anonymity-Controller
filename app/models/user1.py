"""
User Model for the Anonymity Controller
Stores user information and preferences
"""
from app.extensions import db
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash


class User(db.Model):
    """
    User model for authentication and tracking
    """
    __tablename__ = 'users'

    # Primary Key
    id = db.Column(db.Integer, primary_key=True)

    # Basic Information
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255))

    # User Profile
    full_name = db.Column(db.String(150))
    department = db.Column(db.String(50), default='guest')
    risk_level = db.Column(db.String(20), default='medium')  # low, medium, high
    clearance_level = db.Column(db.Integer, default=0)
    priority = db.Column(db.String(20), default='standard')  # low, standard, high

    # Request Limits
    max_requests_per_day = db.Column(db.Integer, default=50)
    max_concurrent_requests = db.Column(db.Integer, default=5)

    # Preferences
    preferred_backend = db.Column(db.String(20), default='auto')  # auto, http, https, tor
    enable_fingerprint_protection = db.Column(db.Boolean, default=True)
    enable_logging = db.Column(db.Boolean, default=True)

    # Status
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    last_request = db.Column(db.DateTime)

    # Relationships
    requests = db.relationship('RequestLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    def __init__(self, username, email, password=None, **kwargs):
        """Initialize user with required fields"""
        self.username = username
        self.email = email
        if password:
            self.set_password(password)

        # Set optional fields from kwargs
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def set_password(self, password):
        """Hash and set user password"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verify password against hash"""
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    def get_request_count_today(self):
        """Get number of requests made today"""
        from datetime import date
        today_start = datetime.combine(date.today(), datetime.min.time())
        return self.requests.filter(RequestLog.timestamp >= today_start).count()

    def can_make_request(self):
        """Check if user can make another request"""
        if not self.is_active:
            return False, "User account is inactive"

        today_count = self.get_request_count_today()
        if today_count >= self.max_requests_per_day:
            return False, f"Daily request limit reached ({self.max_requests_per_day})"

        return True, "OK"

    def to_dict(self):
        """Convert user object to dictionary"""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'full_name': self.full_name,
            'department': self.department,
            'risk_level': self.risk_level,
            'clearance_level': self.clearance_level,
            'priority': self.priority,
            'max_requests_per_day': self.max_requests_per_day,
            'preferred_backend': self.preferred_backend,
            'enable_fingerprint_protection': self.enable_fingerprint_protection,
            'is_active': self.is_active,
            'is_admin': self.is_admin,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'requests_today': self.get_request_count_today()
        }

    def __repr__(self):
        return f'<User {self.username}>'
