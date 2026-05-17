import pytest
from app import app as flask_app
from models import db
from init_db import init_database

@pytest.fixture
def app():
    flask_app.config['TESTING'] = True
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    with flask_app.app_context():
        db.create_all()
        init_database()
        yield flask_app
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()
