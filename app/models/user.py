"""
User Model - Enhanced with security utilities
Stores user information and preferences with secure password handling
"""
from app.extensions import db
from app.utils.security import SecurityUtils, PasswordValidator
from app.utils.validators import InputValidator
from datetime import datetime
import logging

logger = logging.getLogger(__name__)


class User(db.Model):
    """
    User model for authentication and tracking with enhanced security
    """
    __tablename__ = 'users'

    # Primary Key
    id = db.Column(db.Integer, primary_key=True)

    # Basic Information
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255))

    # Security
    api_key = db.Column(db.String(100), unique=True, index=True)  # For API access
    api_key_hash = db.Column(db.String(255))  # Hashed API key

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
    is_verified = db.Column(db.Boolean, default=False)

    # Security tracking
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime)
    password_changed_at = db.Column(db.DateTime)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    last_request = db.Column(db.DateTime)

    # Relationships
    requests = db.relationship('RequestLog', backref='user', lazy='dynamic', cascade='all, delete-orphan')

    def __init__(self, username, email, password=None, **kwargs):
        """
        Initialize user with validation

        Args:
            username: Username (will be validated)
            email: Email address (will be validated)
            password: Plain text password (will be validated and hashed)
            **kwargs: Additional user attributes
        """
        # Validate username
        is_valid, msg = InputValidator.is_valid_username(username)
        if not is_valid:
            raise ValueError(f"Invalid username: {msg}")

        # Validate email
        is_valid, msg = InputValidator.is_valid_email(email)
        if not is_valid:
            raise ValueError(f"Invalid email: {msg}")

        self.username = username
        self.email = email

        if password:
            self.set_password(password)

        # Set optional fields from kwargs
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

        logger.info(f"New user created: {username}")

    def set_password(self, password):
        """
        Validate and hash user password

        Args:
            password: Plain text password

        Raises:
            ValueError: If password doesn't meet strength requirements
        """
        # Validate password strength
        is_valid, msg = PasswordValidator.validate_password_strength(password)
        if not is_valid:
            raise ValueError(msg)

        # Check against common passwords
        if PasswordValidator.is_common_password(password):
            raise ValueError("Password is too common. Please choose a stronger password.")

        # Hash password using SecurityUtils
        self.password_hash = SecurityUtils.hash_password(password)
        self.password_changed_at = datetime.utcnow()
        self.failed_login_attempts = 0  # Reset on password change

        logger.info(f"Password updated for user: {self.username}")

    def check_password(self, password):
        """
        Verify password against hash

        Args:
            password: Plain text password to verify

        Returns:
            True if password matches, False otherwise
        """
        if not self.password_hash:
            return False

        is_valid = SecurityUtils.verify_password(password, self.password_hash)

        if is_valid:
            # Reset failed attempts on successful login
            self.failed_login_attempts = 0
            self.last_login = datetime.utcnow()
            logger.info(f"Successful login for user: {self.username}")
        else:
            # Increment failed attempts
            self.failed_login_attempts += 1
            logger.warning(f"Failed login attempt for user: {self.username} (attempt {self.failed_login_attempts})")

            # Lock account after 5 failed attempts
            if self.failed_login_attempts >= 5:
                from datetime import timedelta
                self.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
                logger.warning(f"Account locked for user: {self.username}")

        return is_valid

    def is_account_locked(self):
        """Check if account is currently locked"""
        if not self.account_locked_until:
            return False

        if datetime.utcnow() < self.account_locked_until:
            return True

        # Unlock account if lock period has expired
        self.account_locked_until = None
        self.failed_login_attempts = 0
        return False

    def generate_api_key(self):
        """Generate a new API key for this user"""
        api_key = SecurityUtils.generate_api_key()
        self.api_key_hash = SecurityUtils.hash_string(api_key)

        logger.info(f"API key generated for user: {self.username}")

        # Return the plain API key (only time it's visible)
        return api_key

    def verify_api_key(self, api_key):
        """Verify an API key against the stored hash"""
        if not self.api_key_hash:
            return False

        key_hash = SecurityUtils.hash_string(api_key)
        return SecurityUtils.constant_time_compare(key_hash, self.api_key_hash)

    def get_request_count_today(self):
        """Get number of requests made today"""
        from datetime import date
        today_start = datetime.combine(date.today(), datetime.min.time())
        return self.requests.filter(RequestLog.timestamp >= today_start).count()

    def can_make_request(self):
        """
        Check if user can make another request

        Returns:
            Tuple of (can_make_request, reason)
        """
        if not self.is_active:
            return False, "User account is inactive"

        if self.is_account_locked():
            return False, "Account is temporarily locked due to failed login attempts"

        today_count = self.get_request_count_today()
        if today_count >= self.max_requests_per_day:
            return False, f"Daily request limit reached ({self.max_requests_per_day})"

        return True, "OK"

    def to_dict(self, include_sensitive=False):
        """
        Convert user object to dictionary

        Args:
            include_sensitive: Whether to include sensitive information

        Returns:
            Dictionary representation of user
        """
        user_dict = {
            'id': self.id,
            'username': self.username,
            'email': SecurityUtils.mask_sensitive_data(self.email) if not include_sensitive else self.email,
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
            'is_verified': self.is_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'requests_today': self.get_request_count_today()
        }

        if include_sensitive:
            user_dict['has_api_key'] = bool(self.api_key_hash)
            user_dict['failed_login_attempts'] = self.failed_login_attempts
            user_dict['account_locked'] = self.is_account_locked()

        return user_dict

    def __repr__(self):
        return f'<User {self.username}>'


# Import RequestLog to avoid circular imports
from app.models.request_log import RequestLog
