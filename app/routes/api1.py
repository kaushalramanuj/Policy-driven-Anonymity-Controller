"""
API Routes - RESTful API endpoints for the anonymity controller
"""
from flask import Blueprint, request, jsonify, session
from app.services.anonymity_service import AnonymityService
import uuid

api_bp = Blueprint('api', __name__)
anonymity_service = AnonymityService()


@api_bp.route('/request', methods=['POST'])
def api_make_request():
    """
    API endpoint to make anonymity requests

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
            return jsonify({'error': 'JSON payload required'}), 400

        if not data.get('target_url'):
            return jsonify({'error': 'target_url is required'}), 400

        # Get or generate user ID
        user_id = data.get('user_id') or session.get('session_id') or str(uuid.uuid4())

        # Process the request
        result = anonymity_service.process_anonymity_request(user_id, data)

        return jsonify(result)

    except Exception as e:
        return jsonify({'error': f'API request failed: {str(e)}'}), 500


@api_bp.route('/status', methods=['GET'])
def api_system_status():
    """Get system status via API"""
    try:
        status = anonymity_service.get_system_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/backends', methods=['GET'])
def api_available_backends():
    """Get available backend information"""
    try:
        proxy_stats = anonymity_service.proxy_manager.get_proxy_stats()
        return jsonify({
            'available_backends': proxy_stats['available_backends'],
            'descriptions': {
                'tor': 'High anonymity, slower speed',
                'https': 'Medium anonymity, medium speed',
                'http': 'Low anonymity, fast speed',
                'direct': 'No anonymity, fastest speed'
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@api_bp.route('/user/<user_id>/stats', methods=['GET'])
def api_user_stats(user_id):
    """Get statistics for a specific user"""
    try:
        stats = anonymity_service.get_user_statistics(user_id)
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500
