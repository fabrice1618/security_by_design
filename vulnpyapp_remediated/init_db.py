from app import app
from extensions import db
from models import User, Product, Order, Comment


def init_database():
    with app.app_context():
        db.drop_all()
        db.create_all()

        admin = User(email='admin@vulnpyapp.local', username='admin',
                     is_admin=True, bio='Administrator account')
        admin.set_password('Admin123!')

        alice = User(email='alice@vulnpyapp.local', username='alice',
                     is_admin=False, bio='Regular user Alice')
        alice.set_password('Alice123!')

        bob = User(email='bob@vulnpyapp.local', username='bob',
                   is_admin=False, bio='Regular user Bob')
        bob.set_password('Bob123!')

        db.session.add_all([admin, alice, bob])
        db.session.commit()

        products = [
            Product(name='Security Handbook', description='OWASP guide',
                    price=39.99, stock=10),
            Product(name='USB Rubber Ducky', description='Pentesting tool',
                    price=49.99, stock=5),
            Product(name='Kali Linux Sticker', description='Cool sticker',
                    price=2.99, stock=100),
        ]
        db.session.add_all(products)

        orders = [
            Order(user_id=admin.id, product_name='Security Handbook',
                  amount=39.99, shipping_address='Admin HQ'),
            Order(user_id=alice.id, product_name='USB Rubber Ducky',
                  amount=49.99, shipping_address='123 Alice Street'),
            Order(user_id=alice.id, product_name='Kali Linux Sticker',
                  amount=2.99, shipping_address='123 Alice Street'),
            Order(user_id=bob.id, product_name='Security Handbook',
                  amount=39.99, shipping_address='456 Bob Avenue'),
        ]
        db.session.add_all(orders)

        comments = [
            Comment(user_id=alice.id, content='Great product, recommended!'),
            Comment(user_id=bob.id, content='Fast shipping, very satisfied.'),
        ]
        db.session.add_all(comments)

        db.session.commit()
        print("✅ Database initialized (bcrypt hashes)")


if __name__ == '__main__':
    init_database()
