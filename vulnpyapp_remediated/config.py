import os
import secrets
from dotenv import load_dotenv

load_dotenv()


class Config:
    """Configuration de base sécurisée"""

    # ✅ Clé secrète obligatoire en prod, générée aléatoirement sinon
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

    # Base de données
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'sqlite:///vulnpyapp.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        'pool_pre_ping': True,
        'pool_recycle': 3600,
    }

    # ✅ Cookies sécurisés
    SESSION_COOKIE_SECURE = True       # HTTPS uniquement
    SESSION_COOKIE_HTTPONLY = True     # Inaccessible en JS
    SESSION_COOKIE_SAMESITE = 'Strict' # Protection CSRF renforcée
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes
    SESSION_COOKIE_NAME = '__Host-session'

    # ✅ CSRF
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # Upload
    UPLOAD_FOLDER = os.path.abspath('uploads')
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg'}

    # Rate limiting
    RATELIMIT_DEFAULT = "200 per hour"
    RATELIMIT_STORAGE_URI = "memory://"

    # ✅ Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')


class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

    def __init__(self):
        if not os.environ.get('SECRET_KEY'):
            raise RuntimeError("SECRET_KEY must be set in production")


class DevelopmentConfig(Config):
    DEBUG = True
    # En dev local sans HTTPS, on relâche Secure (à documenter)
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_NAME = 'session'  # __Host- exige Secure


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False  # Désactivé pour les tests unitaires
    SESSION_COOKIE_SECURE = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
