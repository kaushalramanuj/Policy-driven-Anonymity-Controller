"""
API Routes - Enhanced with comprehensive validation
RESTful API endpoints for the anonymity controller
"""
from flask import Blueprint, request, jsonify, session
from app.services.anonymity_service import AnonymityService
from app.utils.validators import URLValidator, RequestValidator, InputValidator, RateLimitValidator
from app.utils.security import SecurityUtils
import uuid
import logging
from functools import wraps

api_bp = Blueprint('api', __name__)
anonymity_service = AnonymityService()
logger = logging.getLogger(__name__)

# Simple in-memory rate limiting (use Redis in production)
rate_limit_store = {}


def require_api_validation(f):
    """Decorator to validate API requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Validate Content-Type for POST requests
        if request.method == 'POST':
            if not request.is_json:
                return jsonify({'error': 'Content-Type must be application/json'}), 400

        # Basic rate limiting (simplified)
        user_id = request.headers.get('X-User-ID') or session.get('session_id', 'anonymous')
        rate_key = f"{user_id}:{request.endpoint}"

        current_count = rate_limit_store.get(rate_key, 0)
        is_allowed, msg = RateLimitValidator.check_rate_limit(current_count, 100, "hour")

        if not is_allowed:
            logger.warning(f"Rate limit exceeded for {user_id[:8]}...")
            return jsonify({'error': msg}), 429

        rate_limit_store[rate_key] = current_count + 1

        return f(*args, **kwargs)
    return decorated_function


@api_bp.route('/request', methods=['POST'])
@require_api_validation
def api_make_request():
    """
    API endpoint to make anonymity requests with comprehensive validation

    Expected JSON payload:
    {
        "target_url": "https://example.com",
        "method": "GET",
        "headers": {},
        "data": {},
        "preferences": {
            "backend": "auto",
            "fingerprint_protection": true
        },
        "user_id": "optional-user-id"
    }
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                'error': 'JSON payload required',
                'example': {
                    'target_url': 'https://example.com',
                    'method': 'GET',
                    'preferences': {'backend': 'auto'}
                }
            }), 400

        # Validate target URL (required)
        target_url = data.get('target_url')
        if not target_url:
            return jsonify({'error': 'target_url is required'}), 400

        is_valid, msg = URLValidator.is_valid_url(target_url)
        if not is_valid:
            return jsonify({'error': f'Invalid target_url: {msg}'}), 400

        # Check blocked domains
        is_allowed, msg = URLValidator.is_allowed_domain(
            target_url,
            blocked_domains=['malicious-site.com', 'spam-site.xyz']
        )
        if not is_allowed:
            return jsonify({'error': msg}), 403

        # Validate HTTP method
        method = data.get('method', 'GET')
        is_valid, msg = RequestValidator.validate_http_method(method)
        if not is_valid:
            return jsonify({'error': f'Invalid method: {msg}'}), 400

        # Validate backend preference
        backend = data.get('preferences', {}).get('backend', 'auto')
        is_valid, msg = RequestValidator.validate_backend_type(backend)
        if not is_valid:
            return jsonify({'error': f'Invalid backend: {msg}'}), 400

        # Validate headers
        headers = data.get('headers', {})
        if headers:
            is_valid, msg = RequestValidator.validate_headers(headers)
            if not is_valid:
                return jsonify({'error': f'Invalid headers: {msg}'}), 400

        # Validate request data
        request_data = data.get('data')
        is_valid, msg = RequestValidator.validate_request_data(request_data, method)
        if not is_valid:
            return jsonify({'error': msg}), 400

        # Get or generate user ID
        user_id = data.get('user_id')
        if user_id:
            # Validate provided user ID
            sanitized_user_id = InputValidator.sanitize_input(user_id, max_length=128)
            if not sanitized_user_id:
                return jsonify({'error': 'Invalid user_id format'}), 400
            user_id = sanitized_user_id
        else:
            # Use session ID or generate new one
            user_id = session.get('session_id')
            if not user_id:
                user_id = SecurityUtils.generate_session_id()
                session['session_id'] = user_id

        logger.info(f"API request from {user_id[:8]}... to {URLValidator.extract_domain(target_url)}")

        # Process the request
        result = anonymity_service.process_anonymity_request(user_id, data)

        # Add API metadata to response
        result['api_version'] = '1.0'
        result['request_id'] = SecurityUtils.generate_secure_token(16)

        return jsonify(result)

    except Exception as e:
        logger.error(f"API request failed: {str(e)}", exc_info=True)
        return jsonify({
            'error': f'API request failed: {str(e)}',
            'success': False
        }), 500


@api_bp.route('/status', methods=['GET'])
def api_system_status():
    """Get system status via API"""
    try:
        status = anonymity_service.get_system_status()
        status['api_version'] = '1.0'
        status['timestamp'] = datetime.now().isoformat()
        return jsonify(status)
    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/backends', methods=['GET'])
def api_available_backends():
    """Get available backend information"""
    try:
        proxy_stats = anonymity_service.proxy_manager.get_proxy_stats()
        return jsonify({
            'available_backends': proxy_stats['available_backends'],
            'descriptions': {
                'tor': {
                    'name': 'Tor Network',
                    'anonymity': 'high',
                    'speed': 'slow',
                    'description': 'Maximum anonymity through onion routing'
                },
                'https': {
                    'name': 'HTTPS Proxy',
                    'anonymity': 'medium',
                    'speed': 'medium',
                    'description': 'Encrypted proxy connection'
                },
                'http': {
                    'name': 'HTTP Proxy',
                    'anonymity': 'low',
                    'speed': 'fast',
                    'description': 'Basic proxy forwarding'
                },
                'direct': {
                    'name': 'Direct Connection',
                    'anonymity': 'none',
                    'speed': 'fastest',
                    'description': 'No anonymization layer'
                }
            },
            'api_version': '1.0'
        })
    except Exception as e:
        logger.error(f"Failed to get backends: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/user/<user_id>/stats', methods=['GET'])
def api_user_stats(user_id):
    """Get statistics for a specific user with validation"""
    try:
        # Sanitize and validate user ID
        user_id = InputValidator.sanitize_input(user_id, max_length=128)
        if not user_id:
            return jsonify({'error': 'Invalid user_id'}), 400

        stats = anonymity_service.get_user_statistics(user_id)
        stats['api_version'] = '1.0'
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Failed to get user stats: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.route('/validate/url', methods=['POST'])
@require_api_validation
def validate_url():
    """Validate a URL without making a request"""
    try:
        data = request.get_json()
        url = data.get('url')

        if not url:
            return jsonify({'error': 'url parameter required'}), 400

        # Validate URL format
        is_valid, msg = URLValidator.is_valid_url(url)

        # Check domain allowance
        is_allowed, domain_msg = URLValidator.is_allowed_domain(
            url,
            blocked_domains=['malicious-site.com', 'spam-site.xyz']
        )

        # Extract domain
        domain = URLValidator.extract_domain(url)

        return jsonify({
            'url': url,
            'valid': is_valid,
            'message': msg,
            'domain_allowed': is_allowed,
            'domain_message': domain_msg,
            'domain': domain,
            'api_version': '1.0'
        })

    except Exception as e:
        logger.error(f"URL validation failed: {e}")
        return jsonify({'error': str(e)}), 500


@api_bp.errorhandler(400)
def bad_request(error):
    """Handle 400 errors"""
    return jsonify({'error': 'Bad request', 'api_version': '1.0'}), 400


@api_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Endpoint not found', 'api_version': '1.0'}), 404


@api_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error', 'api_version': '1.0'}), 500
