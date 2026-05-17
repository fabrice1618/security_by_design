import pytest
from app import create_app
from extensions import db as _db
from models import User, Product, Order, Comment


@pytest.fixture(scope='session')
def app():
    app = create_app('testing')
    with app.app_context():
        _db.create_all()
        _seed_db()
        yield app
        _db.drop_all()


@pytest.fixture(scope='function')
def client(app):
    return app.test_client()


@pytest.fixture(scope='function')
def auth_client(client):
    """Client authentifié en tant qu'alice (non-admin)"""
    client.post('/login', data={
        'email': 'alice@vulnpyapp.local',
        'password': 'Alice123!'
    })
    return client


@pytest.fixture(scope='function')
def admin_client(client):
    """Client authentifié en tant qu'admin"""
    client.post('/login', data={
        'email': 'admin@vulnpyapp.local',
        'password': 'Admin123!'
    })
    return client


def _seed_db():
    admin = User(email='admin@vulnpyapp.local', username='admin', is_admin=True)
    admin.set_password('Admin123!')

    alice = User(email='alice@vulnpyapp.local', username='alice', is_admin=False)
    alice.set_password('Alice123!')

    bob = User(email='bob@vulnpyapp.local', username='bob', is_admin=False)
    bob.set_password('Bobby123!')

    _db.session.add_all([admin, alice, bob])
    _db.session.commit()

    products = [
        Product(name='Security Handbook', description='OWASP guide',
                price=39.99, stock=10),
        Product(name='USB Rubber Ducky', description='Pentesting tool',
                price=49.99, stock=5),
    ]
    _db.session.add_all(products)

    orders = [
        Order(user_id=alice.id, product_name='Security Handbook',
              amount=39.99, shipping_address='123 Alice Street'),
        Order(user_id=bob.id, product_name='USB Rubber Ducky',
              amount=49.99, shipping_address='456 Bob Avenue'),
    ]
    _db.session.add_all(orders)

    comments = [
        Comment(user_id=alice.id, content='Great product!'),
        Comment(user_id=bob.id, content='Fast shipping!'),
    ]
    _db.session.add_all(comments)
    _db.session.commit()
