"""
Configuration settings for the application
"""
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///anonymity_controller.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Open Policy Agent Configuration
    OPA_URL = os.environ.get('OPA_URL') or 'http://localhost:8181/v1/data/anonymity/allow'
    OPA_SECURED = True

    # Proxy Configuration
    DEFAULT_HTTP_PROXIES = [
        'http://proxy1.example.com:8080',
        'http://proxy2.example.com:8080',
    ]
    DEFAULT_HTTPS_PROXIES = [
        'https://proxy1.example.com:8443',
        'https://proxy2.example.com:8443',
    ]

    # Tor Configuration
    TOR_SOCKS_PORT = 9050
    TOR_CONTROL_PORT = 9051
    TOR_PASSWORD = os.environ.get('TOR_PASSWORD') or ''

    # Selenium Configuration
    WEBDRIVER_PATH = os.environ.get('WEBDRIVER_PATH')
    SELENIUM_HEADLESS = True

    # Security Settings
    SESSION_TIMEOUT = 3600  # 1 hour
    MAX_REQUESTS_PER_MINUTE = 60


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    OPA_SECURED = False  # Disable OPA for development


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    # Add production-specific settings


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
