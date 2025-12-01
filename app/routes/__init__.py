"""
Routes package initialization
Import all blueprints here to make them available for registration
"""
from .main import main_bp
from .api import api_bp
from .policy import policy_bp

__all__ = ['main_bp', 'api_bp', 'policy_bp']
