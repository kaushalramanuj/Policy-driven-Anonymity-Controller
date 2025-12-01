"""
Input Validation Utilities for the Anonymity Controller
Validates user inputs and request data
"""
import re
from typing import Optional, Tuple
from urllib.parse import urlparse


class URLValidator:
    """
    URL validation utilities
    """

    @staticmethod
    def is_valid_url(url: str) -> Tuple[bool, str]:
        """
        Validate if a string is a valid URL

        Args:
            url: URL string to validate

        Returns:
            Tuple of (is_valid, message)
        """
        if not url:
            return False, "URL cannot be empty"

        if len(url) > 2048:
            return False, "URL is too long (max 2048 characters)"

        try:
            result = urlparse(url)

            # Check for scheme
            if not result.scheme:
                return False, "URL must include a scheme (http:// or https://)"

            # Only allow http and https
            if result.scheme not in ['http', 'https']:
                return False, "Only HTTP and HTTPS URLs are allowed"

            # Check for netloc (domain)
            if not result.netloc:
                return False, "URL must include a domain"

            # Check for invalid characters
            if any(c in url for c in [' ', '<', '>', '{', '}', '|', '\\', '^', '`']):
                return False, "URL contains invalid characters"

            return True, "Valid URL"

        except Exception as e:
            return False, f"Invalid URL format: {str(e)}"

    @staticmethod
    def is_allowed_domain(url: str, allowed_domains: list = None, blocked_domains: list = None) -> Tuple[bool, str]:
        """
        Check if URL domain is allowed

        Args:
            url: URL to check
            allowed_domains: List of allowed domains (if None, all are allowed)
            blocked_domains: List of blocked domains

        Returns:
            Tuple of (is_allowed, message)
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Remove port if present
            if ':' in domain:
                domain = domain.split(':')[0]

            # Check blocked domains
            if blocked_domains:
                for blocked in blocked_domains:
                    if domain == blocked.lower() or domain.endswith('.' + blocked.lower()):
                        return False, f"Domain {domain} is blocked"

            # Check allowed domains
            if allowed_domains:
                for allowed in allowed_domains:
                    if domain == allowed.lower() or domain.endswith('.' + allowed.lower()):
                        return True, "Domain is allowed"

                return False, f"Domain {domain} is not in the allowed list"

            return True, "Domain is allowed"

        except Exception as e:
            return False, f"Error checking domain: {str(e)}"

    @staticmethod
    def extract_domain(url: str) -> Optional[str]:
        """
        Extract domain from URL

        Args:
            url: URL string

        Returns:
            Domain name or None if invalid
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc

            # Remove port
            if ':' in domain:
                domain = domain.split(':')[0]

            return domain.lower()
        except:
            return None


class InputValidator:
    """
    General input validation utilities
    """

    @staticmethod
    def is_valid_username(username: str) -> Tuple[bool, str]:
        """
        Validate username format

        Args:
            username: Username to validate

        Returns:
            Tuple of (is_valid, message)
        """
        if not username:
            return False, "Username cannot be empty"

        if len(username) < 3:
            return False, "Username must be at least 3 characters"

        if len(username) > 50:
            return False, "Username must be less than 50 characters"

        # Only allow alphanumeric, underscore, and hyphen
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username can only contain letters, numbers, underscore, and hyphen"

        # Must start with a letter
        if not username[0].isalpha():
            return False, "Username must start with a letter"

        return True, "Valid username"

    @staticmethod
    def is_valid_email(email: str) -> Tuple[bool, str]:
        """
        Validate email address format

        Args:
            email: Email address to validate

        Returns:
            Tuple of (is_valid, message)
        """
        if not email:
            return False, "Email cannot be empty"

        if len(email) > 320:
            return False, "Email is too long"

        # Basic email regex pattern
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

        if not re.match(pattern, email):
            return False, "Invalid email format"

        return True, "Valid email"

    @staticmethod
    def is_valid_session_id(session_id: str) -> bool:
        """
        Validate session ID format

        Args:
            session_id: Session ID to validate

        Returns:
            True if valid, False otherwise
        """
        if not session_id:
            return False

        # Session IDs should be alphanumeric and of reasonable length
        if len(session_id) < 16 or len(session_id) > 128:
            return False

        # Check if it's URL-safe base64 or hex
        if not re.match(r'^[a-zA-Z0-9_-]+$', session_id):
            return False

        return True

    @staticmethod
    def sanitize_input(text: str, max_length: int = 1000) -> str:
        """
        Sanitize user input by removing potentially dangerous characters

        Args:
            text: Input text to sanitize
            max_length: Maximum allowed length

        Returns:
            Sanitized text
        """
        if not text:
            return ""

        # Truncate to max length
        text = text[:max_length]

        # Remove control characters
        text = ''.join(char for char in text if ord(char) >= 32 or char in '\n\r\t')

        # Remove potential HTML/script tags
        text = re.sub(r'<[^>]+>', '', text)

        return text.strip()

    @staticmethod
    def is_valid_port(port: int) -> Tuple[bool, str]:
        """
        Validate port number

        Args:
            port: Port number to validate

        Returns:
            Tuple of (is_valid, message)
        """
        if not isinstance(port, int):
            return False, "Port must be an integer"

        if port < 1 or port > 65535:
            return False, "Port must be between 1 and 65535"

        # Warn about privileged ports
        if port < 1024:
            return True, "Valid port (privileged - requires root/admin)"

        return True, "Valid port"


class RequestValidator:
    """
    Validate anonymity request parameters
    """

    @staticmethod
    def validate_http_method(method: str) -> Tuple[bool, str]:
        """
        Validate HTTP method

        Args:
            method: HTTP method string

        Returns:
            Tuple of (is_valid, message)
        """
        allowed_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS']

        if not method:
            return False, "HTTP method cannot be empty"

        method = method.upper()

        if method not in allowed_methods:
            return False, f"HTTP method must be one of: {', '.join(allowed_methods)}"

        return True, "Valid HTTP method"

    @staticmethod
    def validate_backend_type(backend: str) -> Tuple[bool, str]:
        """
        Validate backend type selection

        Args:
            backend: Backend type string

        Returns:
            Tuple of (is_valid, message)
        """
        allowed_backends = ['auto', 'direct', 'http', 'https', 'tor']

        if not backend:
            return False, "Backend type cannot be empty"

        backend = backend.lower()

        if backend not in allowed_backends:
            return False, f"Backend must be one of: {', '.join(allowed_backends)}"

        return True, "Valid backend type"

    @staticmethod
    def validate_headers(headers: dict) -> Tuple[bool, str]:
        """
        Validate HTTP headers dictionary

        Args:
            headers: Dictionary of HTTP headers

        Returns:
            Tuple of (is_valid, message)
        """
        if not isinstance(headers, dict):
            return False, "Headers must be a dictionary"

        # Check header names
        for key in headers.keys():
            if not isinstance(key, str):
                return False, "Header names must be strings"

            # Header names should only contain certain characters
            if not re.match(r'^[a-zA-Z0-9-]+$', key):
                return False, f"Invalid header name: {key}"

        # Check header values
        for value in headers.values():
            if not isinstance(value, str):
                return False, "Header values must be strings"

            # Check for control characters
            if any(ord(c) < 32 and c not in '\n\r\t' for c in value):
                return False, "Header values contain invalid characters"

        return True, "Valid headers"

    @staticmethod
    def validate_request_data(data: dict, method: str) -> Tuple[bool, str]:
        """
        Validate request data based on HTTP method

        Args:
            data: Request data dictionary
            method: HTTP method

        Returns:
            Tuple of (is_valid, message)
        """
        method = method.upper()

        # GET and DELETE typically don't have body data
        if method in ['GET', 'DELETE', 'HEAD'] and data:
            return False, f"{method} requests should not have body data"

        # POST, PUT, PATCH require data
        if method in ['POST', 'PUT', 'PATCH']:
            if not data:
                return True, "No data provided (optional)"

            if not isinstance(data, dict):
                return False, "Request data must be a dictionary"

        return True, "Valid request data"


class RateLimitValidator:
    """
    Rate limiting validation utilities
    """

    @staticmethod
    def check_rate_limit(current_count: int, max_count: int, time_window: str = "hour") -> Tuple[bool, str]:
        """
        Check if rate limit is exceeded

        Args:
            current_count: Current request count
            max_count: Maximum allowed requests
            time_window: Time window description

        Returns:
            Tuple of (is_allowed, message)
        """
        if current_count >= max_count:
            return False, f"Rate limit exceeded: {current_count}/{max_count} requests per {time_window}"

        remaining = max_count - current_count
        return True, f"Rate limit OK: {remaining} requests remaining"
