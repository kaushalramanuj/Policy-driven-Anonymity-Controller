"""
Security Utilities for the Anonymity Controller
Provides security-related helper functions
"""
import hashlib
import secrets
import string
import re
from datetime import datetime, timedelta
from typing import Optional, Tuple
import jwt
from werkzeug.security import generate_password_hash, check_password_hash


class SecurityUtils:
    """
    Collection of security utility functions
    """

    @staticmethod
    def generate_secure_token(length: int = 32) -> str:
        """
        Generate a cryptographically secure random token

        Args:
            length: Length of the token to generate

        Returns:
            Secure random token string
        """
        alphabet = string.ascii_letters + string.digits
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    @staticmethod
    def generate_session_id() -> str:
        """
        Generate a secure session ID

        Returns:
            Secure session ID string
        """
        return secrets.token_urlsafe(32)

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using werkzeug's secure method

        Args:
            password: Plain text password

        Returns:
            Hashed password
        """
        return generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)

    @staticmethod
    def verify_password(password: str, password_hash: str) -> bool:
        """
        Verify a password against its hash

        Args:
            password: Plain text password to verify
            password_hash: Stored password hash

        Returns:
            True if password matches, False otherwise
        """
        return check_password_hash(password_hash, password)

    @staticmethod
    def generate_api_key() -> str:
        """
        Generate an API key for programmatic access

        Returns:
            API key string
        """
        return f"anon_{secrets.token_urlsafe(40)}"

    @staticmethod
    def hash_string(text: str) -> str:
        """
        Create SHA-256 hash of a string

        Args:
            text: String to hash

        Returns:
            Hexadecimal hash string
        """
        return hashlib.sha256(text.encode()).hexdigest()

    @staticmethod
    def create_jwt_token(payload: dict, secret_key: str, expiry_hours: int = 24) -> str:
        """
        Create a JWT token for authentication

        Args:
            payload: Data to encode in the token
            secret_key: Secret key for signing
            expiry_hours: Token expiry time in hours

        Returns:
            JWT token string
        """
        expiry = datetime.utcnow() + timedelta(hours=expiry_hours)
        payload['exp'] = expiry
        payload['iat'] = datetime.utcnow()

        return jwt.encode(payload, secret_key, algorithm='HS256')

    @staticmethod
    def verify_jwt_token(token: str, secret_key: str) -> Tuple[bool, Optional[dict]]:
        """
        Verify and decode a JWT token

        Args:
            token: JWT token to verify
            secret_key: Secret key for verification

        Returns:
            Tuple of (is_valid, payload_or_none)
        """
        try:
            payload = jwt.decode(token, secret_key, algorithms=['HS256'])
            return True, payload
        except jwt.ExpiredSignatureError:
            return False, None
        except jwt.InvalidTokenError:
            return False, None

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """
        Sanitize a filename to prevent directory traversal attacks

        Args:
            filename: Original filename

        Returns:
            Sanitized filename
        """
        # Remove directory path components
        filename = filename.replace('/', '_').replace('\\', '_')

        # Remove any non-alphanumeric characters except dots, dashes, and underscores
        filename = re.sub(r'[^a-zA-Z0-9._-]', '_', filename)

        # Limit length
        if len(filename) > 255:
            name, ext = filename.rsplit('.', 1) if '.' in filename else (filename, '')
            filename = name[:250] + ('.' + ext if ext else '')

        return filename

    @staticmethod
    def mask_sensitive_data(data: str, show_chars: int = 4) -> str:
        """
        Mask sensitive data (e.g., email, phone) for logging

        Args:
            data: Sensitive data to mask
            show_chars: Number of characters to show at the end

        Returns:
            Masked string
        """
        if len(data) <= show_chars:
            return '*' * len(data)

        return '*' * (len(data) - show_chars) + data[-show_chars:]

    @staticmethod
    def is_safe_url(url: str, allowed_hosts: list = None) -> bool:
        """
        Check if a URL is safe for redirect (prevents open redirect vulnerabilities)

        Args:
            url: URL to check
            allowed_hosts: List of allowed hostnames

        Returns:
            True if URL is safe, False otherwise
        """
        from urllib.parse import urlparse

        if not url:
            return False

        # Parse the URL
        parsed = urlparse(url)

        # Reject URLs with schemes other than http/https
        if parsed.scheme and parsed.scheme not in ['http', 'https', '']:
            return False

        # If allowed_hosts is specified, check the hostname
        if allowed_hosts and parsed.netloc:
            return parsed.netloc in allowed_hosts

        # If no netloc (relative URL), it's safe
        return not parsed.netloc

    @staticmethod
    def rate_limit_key(user_id: str, endpoint: str) -> str:
        """
        Generate a rate limiting key for a user and endpoint

        Args:
            user_id: User identifier
            endpoint: API endpoint

        Returns:
            Rate limit key
        """
        return f"ratelimit:{user_id}:{endpoint}:{datetime.utcnow().strftime('%Y%m%d%H')}"

    @staticmethod
    def generate_csrf_token() -> str:
        """
        Generate a CSRF token for form protection

        Returns:
            CSRF token string
        """
        return secrets.token_urlsafe(32)

    @staticmethod
    def constant_time_compare(val1: str, val2: str) -> bool:
        """
        Constant-time string comparison to prevent timing attacks

        Args:
            val1: First string
            val2: Second string

        Returns:
            True if strings match, False otherwise
        """
        return secrets.compare_digest(val1.encode(), val2.encode())


class PasswordValidator:
    """
    Password strength validation
    """

    @staticmethod
    def validate_password_strength(password: str) -> Tuple[bool, str]:
        """
        Validate password strength

        Args:
            password: Password to validate

        Returns:
            Tuple of (is_valid, message)
        """
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"

        if len(password) > 128:
            return False, "Password must be less than 128 characters"

        # Check for uppercase
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"

        # Check for lowercase
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"

        # Check for digit
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one digit"

        # Check for special character
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        if not any(c in special_chars for c in password):
            return False, "Password must contain at least one special character"

        return True, "Password is strong"

    @staticmethod
    def is_common_password(password: str) -> bool:
        """
        Check if password is in a list of common passwords

        Args:
            password: Password to check

        Returns:
            True if password is common, False otherwise
        """
        # Common weak passwords
        common_passwords = [
            'password', '123456', '12345678', 'qwerty', 'abc123',
            'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
            'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
            'bailey', 'passw0rd', 'shadow', '123123', '654321'
        ]

        return password.lower() in common_passwords


class IPAddressValidator:
    """
    IP address validation and utilities
    """

    @staticmethod
    def is_valid_ipv4(ip: str) -> bool:
        """
        Check if string is a valid IPv4 address

        Args:
            ip: IP address string

        Returns:
            True if valid IPv4, False otherwise
        """
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False

            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False

            return True
        except (ValueError, AttributeError):
            return False

    @staticmethod
    def is_private_ip(ip: str) -> bool:
        """
        Check if IP address is in a private range

        Args:
            ip: IP address string

        Returns:
            True if private IP, False otherwise
        """
        if not IPAddressValidator.is_valid_ipv4(ip):
            return False

        parts = [int(p) for p in ip.split('.')]

        # Check private ranges
        # 10.0.0.0/8
        if parts[0] == 10:
            return True

        # 172.16.0.0/12
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True

        # 192.168.0.0/16
        if parts[0] == 192 and parts[1] == 168:
            return True

        # 127.0.0.0/8 (localhost)
        if parts[0] == 127:
            return True

        return False
