"""
Main Routes - Handles the web interface for the anonymity controller
"""
from flask import Blueprint, render_template, request, jsonify, session, flash, redirect, url_for
from app.services.anonymity_service import AnonymityService
import uuid
from app.utils.validators import URLValidator, RequestValidator
from app.utils.security import SecurityUtils
from datetime import datetime

main_bp = Blueprint('main', __name__)
anonymity_service = AnonymityService()


@main_bp.route('/')
def dashboard():
    """Main dashboard page"""
    # Generate session ID if not exists
    if 'session_id' not in session:
        session['session_id'] = str(uuid.uuid4())

    # Get system status
    system_status = anonymity_service.get_system_status()

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
    system_status = anonymity_service.get_system_status()
    return render_template('monitoring.html', system_status=system_status)


@main_bp.route('/make-request', methods=['POST'])
def make_anonymity_request():
    """Process an anonymity request from the web interface"""
    try:
        data = request.get_json()

        # Validate URL
        is_valid, msg = URLValidator.is_valid_url(data['target_url'])
        if not is_valid:
            return jsonify({'error': msg}), 400

        # Validate method
        is_valid, msg = RequestValidator.validate_http_method(data['method'])
        if not is_valid:
            return jsonify({'error': msg}), 400
        
        # Get user session ID
        user_id = session.get('session_id', 'anonymous')

        # Prepare request data
        request_data = {
            'target_url': data['target_url'],
            'method': data.get('method', 'GET'),
            'headers': data.get('headers', {}),
            'data': data.get('data'),
            'preferences': {
                'backend': data.get('backend_preference', 'auto'),
                'fingerprint_protection': data.get('fingerprint_protection', True)
            }
        }

        # Process the request
        result = anonymity_service.process_anonymity_request(user_id, request_data)

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': f'Request processing failed: {str(e)}'}), 500


@main_bp.route('/system-status')
def get_system_status():
    """API endpoint to get current system status"""
    try:
        status = anonymity_service.get_system_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@main_bp.route('/user-stats')
def get_user_stats():
    """Get statistics for current user"""
    try:
        user_id = session.get('session_id', 'anonymous')
        stats = anonymity_service.get_user_statistics(user_id)
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@main_bp.route('/test-connection', methods=['POST'])
def test_connection():
    """Test connection to various backends"""
    try:
        data = request.get_json()
        backend_type = data.get('backend', 'auto')

        # Get proxy configuration
        proxy_config = anonymity_service.proxy_manager.get_optimal_proxy(backend_type)

        # Test the connection
        is_working, response_time = anonymity_service.proxy_manager.test_proxy_connection(proxy_config)

        return jsonify({
            'backend': proxy_config['type'],
            'working': is_working,
            'response_time': response_time,
            'metadata': proxy_config.get('metadata', {})
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
