"""
Policy Routes - Handles policy management interface
"""
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from app.services.policy_engine import PolicyEngine

policy_bp = Blueprint('policy', __name__)
policy_engine = PolicyEngine()


@policy_bp.route('/manage')
def manage_policies():
    """Policy management interface"""
    return render_template('policy_manage.html')


@policy_bp.route('/test', methods=['POST'])
def test_policy():
    """Test policy evaluation with sample data"""
    try:
        data = request.get_json()

        # Sample request data for testing
        sample_request = {
            'target_url': data.get('target_url', 'https://example.com'),
            'method': 'GET',
            'timestamp': '2024-01-01T12:00:00',
            'user_agent': 'Mozilla/5.0...',
            'ip_address': '192.168.1.100'
        }

        result = policy_engine.evaluate_anonymity_request('test-user', sample_request)

        return jsonify({
            'test_result': result,
            'sample_input': sample_request
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


@policy_bp.route('/update', methods=['POST'])
def update_policy():
    """Update a policy (advanced feature)"""
    try:
        data = request.get_json()

        policy_name = data.get('policy_name')
        policy_content = data.get('policy_content')

        if not policy_name or not policy_content:
            return jsonify({'error': 'Policy name and content required'}), 400

        success = policy_engine.update_policy(policy_name, policy_content)

        return jsonify({
            'success': success,
            'message': 'Policy updated successfully' if success else 'Policy update failed'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500
