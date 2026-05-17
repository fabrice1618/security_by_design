import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # 🚨 VULNÉRABLE : clé secrète faible et hardcodée
    SECRET_KEY = os.getenv('SECRET_KEY', 'insecure-dev-key')

    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///vulnpyapp.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # 🚨 VULNÉRABLE : cookies sans flags de sécurité
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = False
    SESSION_COOKIE_SAMESITE = None

    UPLOAD_FOLDER = 'uploads'
    MAX_CONTENT_LENGTH = 5 * 1024 * 1024  # 5MB
