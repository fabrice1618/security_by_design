"""
VulnPyApp v2.0 - application remédiée
Toutes les vulnérabilités de la v1.0 ont été corrigées.
"""
import os
import subprocess
from datetime import datetime, timedelta

from flask import (Flask, request, render_template, redirect, url_for,
                   jsonify, send_from_directory, abort, flash)
from flask_login import login_user, logout_user, login_required, current_user
from marshmallow import ValidationError
from werkzeug.utils import secure_filename

from config import config
from extensions import db, login_manager, csrf, limiter, talisman
from models import User, Product, Order, Comment
from schemas import (RegisterSchema, LoginSchema, ProfileUpdateSchema,
                     CommentSchema, PingSchema)
from security import (sanitize_html, admin_required, owns_resource,
                      safe_path, is_safe_host)
from logging_config import configure_logging


def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Init extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # ✅ Talisman : CSP + HSTS + headers de sécurité
    csp = {
        'default-src': "'self'",
        'script-src': ["'self'", "'nonce-{nonce}'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", 'data:'],
        'font-src': "'self'",
        'connect-src': "'self'",
        'frame-ancestors': "'none'",
        'base-uri': "'self'",
        'form-action': "'self'",
        'object-src': "'none'",
    }
    talisman.init_app(
        app,
        content_security_policy=csp,
        content_security_policy_nonce_in=['script-src'],
        force_https=False,  # True en prod réelle
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        strict_transport_security_include_subdomains=True,
        session_cookie_secure=app.config['SESSION_COOKIE_SECURE'],
        session_cookie_http_only=app.config['SESSION_COOKIE_HTTPONLY'],
        session_cookie_samesite=app.config['SESSION_COOKIE_SAMESITE'],
        referrer_policy='no-referrer',
        frame_options='DENY',
        x_content_type_options=True,
    )

    configure_logging(app)
    register_routes(app)
    register_error_handlers(app)

    return app


@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except (ValueError, TypeError):
        return None


# ============================================================
# ROUTES
# ============================================================

def register_routes(app):

    @app.route('/')
    def index():
        products = Product.query.all()
        return render_template('index.html', products=products)

    # --------------------------------------------------------
    # ✅ FIX #1 + #12 + #14 : SQLi login + bcrypt + rate limit
    # --------------------------------------------------------
    @app.route('/login', methods=['GET', 'POST'])
    @limiter.limit("5 per minute", methods=['POST'])
    def login():
        if request.method == 'POST':
            try:
                data = LoginSchema().load(request.form.to_dict())
            except ValidationError as err:
                return render_template('login.html', error='Invalid input'), 400

            # ✅ Requête paramétrée via ORM (pas de SQL string)
            user = User.query.filter_by(email=data['email']).first()

            # ✅ Lockout après 5 échecs
            if user and user.is_locked():
                app.logger.warning(f"Login attempt on locked account: {data['email']}")
                return render_template(
                    'login.html',
                    error='Account temporarily locked. Try again later.'
                ), 429

            # ✅ Comparaison constant-time via bcrypt
            if user and user.check_password(data['password']):
                user.failed_login_attempts = 0
                user.locked_until = None
                db.session.commit()
                login_user(user, remember=False)
                app.logger.info(f"Successful login: user_id={user.id}")
                return redirect(url_for('profile'))

            if user:
                user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
                if user.failed_login_attempts >= 5:
                    user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                    app.logger.warning(f"Account locked: user_id={user.id}")
                db.session.commit()

            # ✅ Message générique (pas de user enumeration)
            app.logger.info(f"Failed login attempt: {data.get('email', '?')}")
            return render_template('login.html', error='Invalid credentials'), 401

        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        app.logger.info(f"Logout: user_id={current_user.id}")
        logout_user()
        return redirect(url_for('index'))

    # --------------------------------------------------------
    # ✅ FIX #8 : Mass Assignment via schema allowlist
    # --------------------------------------------------------
    @app.route('/register', methods=['GET', 'POST'])
    @limiter.limit("3 per minute", methods=['POST'])
    def register():
        if request.method == 'POST':
            try:
                data = RegisterSchema().load(request.form.to_dict())
            except ValidationError as err:
                return render_template('register.html', errors=err.messages), 400

            if User.query.filter_by(email=data['email']).first():
                return render_template(
                    'register.html',
                    errors={'email': ['Already registered']}
                ), 409

            # ✅ Construction explicite : is_admin JAMAIS modifiable
            user = User(
                email=data['email'],
                username=data['username'],
                bio=sanitize_html(data.get('bio', '')),
                is_admin=False  # toujours False à l'inscription
            )
            user.set_password(data['password'])

            db.session.add(user)
            db.session.commit()

            login_user(user)
            app.logger.info(f"New user registered: user_id={user.id}")
            return redirect(url_for('profile'))

        return render_template('register.html')

    # --------------------------------------------------------
    # ✅ FIX #2 + #3 : SQLi search + XSS reflected
    # --------------------------------------------------------
    @app.route('/search')
    def search():
        query_param = (request.args.get('q', '') or '').strip()[:100]
        results = []

        if query_param:
            # ✅ Filtre ORM paramétré (échappement automatique)
            results = Product.query.filter(
                Product.name.ilike(f"%{query_param}%")
            ).limit(50).all()

        # ✅ Pas de |safe → Jinja2 échappe automatiquement
        return render_template('search.html', query=query_param, results=results)

    # --------------------------------------------------------
    # ✅ FIX #4 : XSS Stored via Bleach + échappement
    # --------------------------------------------------------
    @app.route('/comments', methods=['GET', 'POST'])
    def comments():
        if request.method == 'POST':
            if not current_user.is_authenticated:
                return redirect(url_for('login'))

            try:
                data = CommentSchema().load(request.form.to_dict())
            except ValidationError as err:
                flash('Invalid comment', 'error')
                return redirect(url_for('comments'))

            # ✅ Sanitization HTML stricte
            clean_content = sanitize_html(data['content'])

            comment = Comment(user_id=current_user.id, content=clean_content)
            db.session.add(comment)
            db.session.commit()
            return redirect(url_for('comments'))

        all_comments = Comment.query.order_by(Comment.created_at.desc()).limit(100).all()
        return render_template('comments.html', comments=all_comments)

    # --------------------------------------------------------
    # ✅ FIX #5 + #6 : XSS DOM + CSRF
    # --------------------------------------------------------
    @app.route('/profile')
    @login_required
    def profile():
        return render_template('profile.html', user=current_user)

    @app.route('/profile/update', methods=['POST'])
    @login_required
    # ✅ CSRF auto-géré par Flask-WTF (token dans le template)
    def update_profile():
        try:
            data = ProfileUpdateSchema().load(request.form.to_dict())
        except ValidationError as err:
            flash('Invalid data', 'error')
            return redirect(url_for('profile'))

        # ✅ Mise à jour explicite des champs autorisés UNIQUEMENT
        if 'username' in data:
            current_user.username = data['username']
        if 'bio' in data:
            current_user.bio = sanitize_html(data['bio'])

        db.session.commit()
        flash('Profile updated', 'success')
        return redirect(url_for('profile'))

    # --------------------------------------------------------
    # ✅ FIX #7 : IDOR - vérification de propriété
    # --------------------------------------------------------
    @app.route('/api/orders/<int:order_id>')
    @login_required
    def get_order(order_id):
        # ✅ Filtre direct par user_id : aucune fuite possible
        order = Order.query.filter_by(
            id=order_id,
            user_id=current_user.id
        ).first()

        if not order and current_user.is_admin:
            order = Order.query.get(order_id)

        if not order:
            abort(404)

        return jsonify(order.to_dict())

    @app.route('/api/my/orders')
    @login_required
    def my_orders():
        """✅ Endpoint préféré : pas d'ID exposé"""
        orders = Order.query.filter_by(user_id=current_user.id).all()
        return jsonify([o.to_dict() for o in orders])

    @app.route('/api/users/<int:user_id>')
    @login_required
    def get_user(user_id):
        user = User.query.get_or_404(user_id)
        # ✅ Seuls les admins voient les données complètes
        if current_user.id != user.id and not current_user.is_admin:
            # ✅ Données publiques uniquement
            return jsonify(user.to_safe_dict())
        return jsonify({
            **user.to_safe_dict(),
            'email': user.email,
            'is_admin': user.is_admin
        })

    # --------------------------------------------------------
    # ✅ FIX #9 : SSTI - rendu statique
    # --------------------------------------------------------
    @app.route('/hello')
    def hello():
        name = (request.args.get('name', 'World') or 'World')[:50]
        # ✅ Plus de Template() dynamique : passage en variable au template
        # Jinja2 échappe automatiquement → pas de SSTI ni XSS
        return render_template('hello.html', name=name)

    # --------------------------------------------------------
    # ✅ FIX #10 : Path Traversal
    # --------------------------------------------------------
    @app.route('/download')
    @login_required
    def download():
        filename = request.args.get('file', '')

        # ✅ secure_filename + validation extension
        safe_name = secure_filename(filename)
        if not safe_name:
            abort(400)

        if not any(safe_name.lower().endswith(f'.{ext}')
                   for ext in app.config['ALLOWED_EXTENSIONS']):
            abort(400)

        # ✅ Vérification que le chemin reste dans uploads/
        target = safe_path(app.config['UPLOAD_FOLDER'], safe_name)
        if not target or not os.path.isfile(target):
            abort(404)

        # ✅ send_from_directory protège contre le traversal
        return send_from_directory(
            app.config['UPLOAD_FOLDER'],
            safe_name,
            as_attachment=True
        )

    # --------------------------------------------------------
    # ✅ FIX #11 : Command Injection
    # --------------------------------------------------------
    @app.route('/ping', methods=['GET', 'POST'])
    @login_required
    @limiter.limit("10 per minute", methods=['POST'])
    def ping():
        if request.method == 'POST':
            try:
                data = PingSchema().load(request.form.to_dict())
            except ValidationError:
                return render_template('ping.html', error='Invalid host'), 400

            host = data['host']

            # ✅ Double validation
            if not is_safe_host(host):
                app.logger.warning(f"Ping rejected for unsafe host: {host}")
                return render_template('ping.html', error='Host not allowed'), 400

            try:
                # ✅ shell=False + arguments en liste = pas d'injection possible
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '2', host],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    shell=False,
                    check=False
                )
                output = result.stdout + result.stderr
            except subprocess.TimeoutExpired:
                output = "Timeout"
            except Exception as e:
                app.logger.error(f"Ping error: {e}")
                output = "Error executing ping"

            return render_template('ping.html', result=output, host=host)

        return render_template('ping.html')

    # --------------------------------------------------------
    # ✅ Admin panel sécurisé
    # --------------------------------------------------------
    @app.route('/admin')
    @login_required
    @admin_required
    def admin():
        users = User.query.all()
        app.logger.info(f"Admin panel accessed by user_id={current_user.id}")
        return render_template('admin.html', users=users)

    # --------------------------------------------------------
    # ✅ Endpoint debug supprimé en production
    # --------------------------------------------------------
    # /debug/config supprimé volontairement


def register_error_handlers(app):
    """✅ Pages d'erreur génériques sans fuite d'information"""

    @app.errorhandler(400)
    def bad_request(e):
        return render_template('errors/400.html'), 400

    @app.errorhandler(401)
    def unauthorized(e):
        return render_template('errors/401.html'), 401

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(429)
    def rate_limited(e):
        return render_template('errors/429.html'), 429

    @app.errorhandler(500)
    def server_error(e):
        app.logger.exception("Internal server error")
        return render_template('errors/500.html'), 500


# Instance application
app = create_app(os.environ.get('FLASK_ENV', 'default'))


if __name__ == '__main__':
    # ✅ debug=False même en dev (sauf si explicite)
    debug = os.environ.get('FLASK_DEBUG') == '1'
    app.run(host='127.0.0.1', port=5000, debug=debug)
