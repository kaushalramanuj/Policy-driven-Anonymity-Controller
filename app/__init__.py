"""
Application Factory for Policy-Driven Anonymity Controller
"""
from flask import Flask
from app.extensions import db, migrate
from app.routes import main_bp, api_bp, policy_bp
from app.config import Config
import logging
import os


def create_app(config_class=Config):
    """
    Application factory function
    Creates and configures the Flask application instance
    """
    app = Flask(__name__, 
                static_folder='static',
                static_url_path='/static')
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    migrate.init_app(app, db)

    # Register blueprints
    app.register_blueprint(main_bp)
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(policy_bp, url_prefix='/policy')

    # Configure logging
    if not app.debug:
        logging.basicConfig(level=logging.INFO)
        app.logger.info('Anonymity Controller startup')

    return app
