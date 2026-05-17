from datetime import datetime
import bcrypt
from flask_login import UserMixin
from extensions import db


class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    username = db.Column(db.String(80), nullable=False)
    # ✅ bcrypt produit ~60 caractères
    password_hash = db.Column(db.String(60), nullable=False)
    # ✅ is_admin protégé : non modifiable via formulaire
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    bio = db.Column(db.Text, default='')
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    orders = db.relationship('Order', backref='user', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)

    def set_password(self, password: str) -> None:
        """✅ Hashage bcrypt avec cost factor 12"""
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        salt = bcrypt.gensalt(rounds=12)
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def check_password(self, password: str) -> bool:
        """✅ Vérification constante en temps (bcrypt natif)"""
        if not password or not self.password_hash:
            return False
        try:
            return bcrypt.checkpw(
                password.encode('utf-8'),
                self.password_hash.encode('utf-8')
            )
        except (ValueError, TypeError):
            return False

    def is_locked(self) -> bool:
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until

    def to_safe_dict(self) -> dict:
        """✅ Expose UNIQUEMENT les champs publics"""
        return {
            'id': self.id,
            'username': self.username,
            'bio': self.bio
        }


class Product(db.Model):
    __tablename__ = 'products'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    stock = db.Column(db.Integer, default=0)

    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'price': self.price,
            'stock': self.stock
        }


class Order(db.Model):
    __tablename__ = 'orders'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, index=True)
    product_name = db.Column(db.String(120), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    shipping_address = db.Column(db.String(255))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            'id': self.id,
            'product_name': self.product_name,
            'amount': self.amount,
            'shipping_address': self.shipping_address,
            'created_at': self.created_at.isoformat()
        }


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
