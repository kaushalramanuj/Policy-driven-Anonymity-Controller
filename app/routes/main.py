"""
Main Routes - Enhanced with validation utilities and activity logging
Handles the web interface for the anonymity controller
"""
from flask import Blueprint, render_template, request, jsonify, session, flash, redirect, url_for
from app.services.anonymity_service import AnonymityService
from app.utils.validators import URLValidator, RequestValidator, InputValidator
from app.utils.security import SecurityUtils
import uuid
from datetime import datetime
import logging

main_bp = Blueprint('main', __name__)
anonymity_service = AnonymityService()
logger = logging.getLogger(__name__)

# In-memory request history storage (per session)
# In production, use Redis or a database
request_history = {}


def add_to_history(user_id, request_data, result):
    """Store request in history"""
    if user_id not in request_history:
        request_history[user_id] = []
    
    history_entry = {
        'id': str(uuid.uuid4())[:8],
        'url': request_data.get('target_url', 'Unknown'),
        'target_domain': URLValidator.extract_domain(request_data.get('target_url', '')),
        'method': request_data.get('method', 'GET'),
        'backend_used': result.get('backend_used', 'unknown'),
        'success': result.get('success', False),
        'status_code': result.get('response', {}).get('status_code'),
        'response_time': result.get('performance', {}).get('total_time'),
        'fingerprint_protection': result.get('fingerprint_protection', False),
        'risk_level': result.get('policy_metadata', {}).get('risk_level', 'unknown'),
        'timestamp': datetime.now().isoformat(),
        'error': result.get('error') if not result.get('success') else None
    }
    
    # Add to beginning of list (newest first)
    request_history[user_id].insert(0, history_entry)
    
    # Keep only last 50 entries per user
    if len(request_history[user_id]) > 50:
        request_history[user_id] = request_history[user_id][:50]
    
    logger.debug(f"Added request to history for user {user_id[:8]}...")


def get_user_history(user_id, limit=20):
    """Get request history for a user"""
    return request_history.get(user_id, [])[:limit]


@main_bp.route('/')
def dashboard():
    """Main dashboard page"""
    # Generate secure session ID if not exists
    if 'session_id' not in session:
        session['session_id'] = SecurityUtils.generate_session_id()
        logger.info(f"New session created: {session['session_id'][:8]}...")

    # Get system status
    try:
        system_status = anonymity_service.get_system_status()
    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        system_status = {'error': 'Unable to fetch system status'}

    return render_template('dashboard.html', 
                         session_id=session['session_id'],
                         system_status=system_status)


@main_bp.route('/policy-config')
def policy_config():
    """Policy configuration page"""
    return render_template('policy_config.html')


@main_bp.route('/monitoring')
def monitoring():
    """System monitoring page"""
    try:
        system_status = anonymity_service.get_system_status()
    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        system_status = {'error': 'Unable to fetch system status'}

    return render_template('monitoring.html', system_status=system_status)


@main_bp.route('/make-request', methods=['POST'])
def make_anonymity_request():
    """Process an anonymity request from the web interface with validation"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'No data provided'}), 400

        # Validate target URL
        target_url = data.get('target_url', '').strip()
        is_valid, msg = URLValidator.is_valid_url(target_url)
        if not is_valid:
            logger.warning(f"Invalid URL rejected: {target_url}")
            return jsonify({'error': f'Invalid URL: {msg}'}), 400

        # Check against blocked domains
        is_allowed, msg = URLValidator.is_allowed_domain(
            target_url,
            blocked_domains=['malicious-site.com', 'suspicious-domain.org']
        )
        if not is_allowed:
            logger.warning(f"Blocked domain rejected: {target_url}")
            return jsonify({'error': msg}), 403

        # Validate HTTP method
        method = data.get('method', 'GET')
        is_valid, msg = RequestValidator.validate_http_method(method)
        if not is_valid:
            return jsonify({'error': f'Invalid HTTP method: {msg}'}), 400

        # Validate backend preference
        backend = data.get('backend_preference', 'auto')
        is_valid, msg = RequestValidator.validate_backend_type(backend)
        if not is_valid:
            return jsonify({'error': f'Invalid backend type: {msg}'}), 400

        # Validate headers if provided
        headers = data.get('headers', {})
        if headers:
            is_valid, msg = RequestValidator.validate_headers(headers)
            if not is_valid:
                return jsonify({'error': f'Invalid headers: {msg}'}), 400

        # Validate request data based on method
        request_data = data.get('data')
        is_valid, msg = RequestValidator.validate_request_data(request_data, method)
        if not is_valid:
            return jsonify({'error': msg}), 400

        # Get or validate session ID
        user_id = session.get('session_id')
        if not user_id or not InputValidator.is_valid_session_id(user_id):
            user_id = SecurityUtils.generate_session_id()
            session['session_id'] = user_id

        # Prepare validated request data
        validated_request = {
            'target_url': target_url,
            'method': method,
            'headers': headers,
            'data': request_data,
            'preferences': {
                'backend': backend,
                'fingerprint_protection': data.get('fingerprint_protection', True)
            }
        }

        logger.info(f"Processing anonymity request for {user_id[:8]}... to {URLValidator.extract_domain(target_url)}")

        # Process the request
        result = anonymity_service.process_anonymity_request(user_id, validated_request)

        # Store in request history
        add_to_history(user_id, validated_request, result)

        return jsonify(result)

    except Exception as e:
        logger.error(f"Request processing failed: {str(e)}", exc_info=True)
        
        # Store failed request in history
        user_id = session.get('session_id', 'anonymous')
        if user_id:
            add_to_history(user_id, data if data else {}, {
                'success': False,
                'error': str(e)
            })
        
        return jsonify({'error': f'Request processing failed: {str(e)}'}), 500


@main_bp.route('/system-status')
def get_system_status():
    """API endpoint to get current system status"""
    try:
        status = anonymity_service.get_system_status()
        return jsonify(status)
    except Exception as e:
        logger.error(f"Failed to get system status: {e}")
        return jsonify({'error': str(e)}), 500


@main_bp.route('/user-stats')
def get_user_stats():
    """Get statistics for current user with session validation"""
    try:
        user_id = session.get('session_id', 'anonymous')

        # Validate session ID
        if user_id != 'anonymous' and not InputValidator.is_valid_session_id(user_id):
            logger.warning(f"Invalid session ID detected: {user_id}")
            return jsonify({'error': 'Invalid session'}), 400

        stats = anonymity_service.get_user_statistics(user_id)
        
        # Add recent requests to the stats
        stats['recent_requests'] = get_user_history(user_id, limit=20)
        
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Failed to get user stats: {e}")
        return jsonify({'error': str(e)}), 500


@main_bp.route('/activity-log')
def get_activity_log():
    """Get activity log for current user"""
    try:
        user_id = session.get('session_id', 'anonymous')
        
        # Validate session ID
        if user_id != 'anonymous' and not InputValidator.is_valid_session_id(user_id):
            logger.warning(f"Invalid session ID detected: {user_id}")
            return jsonify({'error': 'Invalid session'}), 400
        
        # Get limit from query params (default 20, max 100)
        limit = request.args.get('limit', 20, type=int)
        limit = min(max(1, limit), 100)
        
        history = get_user_history(user_id, limit=limit)
        
        return jsonify({
            'activities': history,
            'total': len(request_history.get(user_id, [])),
            'user_id': user_id[:8] + '...' if len(user_id) > 8 else user_id
        })
    except Exception as e:
        logger.error(f"Failed to get activity log: {e}")
        return jsonify({'error': str(e)}), 500


@main_bp.route('/clear-history', methods=['POST'])
def clear_history():
    """Clear request history for current user"""
    try:
        user_id = session.get('session_id', 'anonymous')
        
        if user_id in request_history:
            request_history[user_id] = []
            logger.info(f"Cleared history for user {user_id[:8]}...")
        
        return jsonify({
            'success': True,
            'message': 'History cleared successfully'
        })
    except Exception as e:
        logger.error(f"Failed to clear history: {e}")
        return jsonify({'error': str(e)}), 500


@main_bp.route('/test-connection', methods=['POST'])
def test_connection():
    """Test connection to various backends with validation"""
    try:
        data = request.get_json()
        backend_type = data.get('backend', 'auto')

        # Validate backend type
        is_valid, msg = RequestValidator.validate_backend_type(backend_type)
        if not is_valid:
            return jsonify({'error': msg}), 400

        # Get proxy configuration
        proxy_config = anonymity_service.proxy_manager.get_optimal_proxy(backend_type)

        # Test the connection
        is_working, response_time = anonymity_service.proxy_manager.test_proxy_connection(proxy_config)

        logger.info(f"Backend test - {backend_type}: {'✓' if is_working else '✗'} ({response_time:.2f}s)")

        return jsonify({
            'backend': proxy_config['type'],
            'working': is_working,
            'response_time': response_time,
            'metadata': proxy_config.get('metadata', {})
        })

    except Exception as e:
        logger.error(f"Connection test failed: {e}")
        return jsonify({'error': str(e)}), 500


@main_bp.route('/verify-tor')
def verify_tor():
    """Verify Tor connectivity"""
    try:
        # Get method from query param (default: both)
        method = request.args.get('method', 'both')
        
        result = {}
        
        if method in ['direct', 'both']:
            # Test with requests library (no fingerprint protection)
            result['direct'] = anonymity_service.verify_tor_connection()
        
        if method in ['fingerprint', 'both']:
            # Test with Selenium (with fingerprint protection)
            result['fingerprint_protected'] = anonymity_service.verify_tor_with_fingerprint_protection()
        
        # Overall status
        if method == 'both':
            result['summary'] = {
                'direct_working': result.get('direct', {}).get('tor_working', False),
                'fingerprint_working': result.get('fingerprint_protected', {}).get('tor_working', False)
            }
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Tor verification failed: {e}")
        return jsonify({
            'error': str(e),
            'status': 'error'
        }), 500


@main_bp.route('/test-fingerprint-tor')
def test_fingerprint_tor():
    """Quick test of Tor through Selenium with fingerprint protection"""
    try:
        result = anonymity_service.verify_tor_with_fingerprint_protection()
        return jsonify(result)
    except Exception as e:
        return jsonify({
            'tor_working': False,
            'error': str(e)
        }), 500


@main_bp.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return render_template('base.html'), 404


@main_bp.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {error}")
    return render_template('base.html'), 500
