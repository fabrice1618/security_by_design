from flask import Flask, request, render_template, redirect, url_for, jsonify, send_file, session, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from sqlalchemy import text
from jinja2 import Template
import os
import subprocess
import hashlib

from config import Config
from models import db, User, Product, Order, Comment

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ============================================================
# ROUTE : Index
# ============================================================
@app.route('/')
def index():
    products = Product.query.all()
    return render_template('index.html', products=products)


# ============================================================
# 🚨 VULN #1 : SQL INJECTION sur le login
# ============================================================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '')
        password = request.form.get('password', '')

        # 🚨 VULNÉRABLE : concaténation SQL directe + MD5
        password_hash = hashlib.md5(password.encode()).hexdigest()
        query = f"SELECT * FROM users WHERE email = '{email}' AND password_hash = '{password_hash}'"

        result = db.session.execute(text(query)).fetchone()

        if result:
            user = User.query.get(result[0])
            login_user(user)
            return redirect(url_for('profile'))
        else:
            return render_template('login.html', error='Invalid credentials')

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


# ============================================================
# 🚨 VULN #8 : MASS ASSIGNMENT sur le register
# ============================================================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # 🚨 VULNÉRABLE : tous les champs du formulaire passent
        data = request.form.to_dict()

        user = User(**{k: v for k, v in data.items() if k != 'password'})
        user.set_password(data.get('password', ''))

        db.session.add(user)
        db.session.commit()

        login_user(user)
        return redirect(url_for('profile'))

    return render_template('register.html')


# ============================================================
# 🚨 VULN #2 & #3 : SQL INJECTION + XSS REFLECTED sur search
# ============================================================
@app.route('/search')
def search():
    query_param = request.args.get('q', '')

    if query_param:
        # 🚨 VULNÉRABLE : SQL injection
        sql = f"SELECT * FROM products WHERE name LIKE '%{query_param}%'"
        try:
            results = db.session.execute(text(sql)).fetchall()
        except Exception as e:
            results = []
    else:
        results = []

    # 🚨 VULNÉRABLE : XSS reflected via |safe
    return render_template('search.html', query=query_param, results=results)


# ============================================================
# 🚨 VULN #4 : XSS STORED sur les commentaires
# ============================================================
@app.route('/comments', methods=['GET', 'POST'])
def comments():
    if request.method == 'POST':
        if not current_user.is_authenticated:
            return redirect(url_for('login'))

        content = request.form.get('content', '')
        # 🚨 VULNÉRABLE : aucune sanitization, stocké tel quel
        comment = Comment(user_id=current_user.id, content=content)
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('comments'))

    all_comments = Comment.query.order_by(Comment.created_at.desc()).all()
    return render_template('comments.html', comments=all_comments)


# ============================================================
# 🚨 VULN #5 : XSS DOM-based sur le profil
# 🚨 VULN #6 : CSRF sur update profile
# ============================================================
@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)


@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    # 🚨 VULNÉRABLE : pas de token CSRF
    current_user.bio = request.form.get('bio', '')
    current_user.username = request.form.get('username', current_user.username)
    db.session.commit()
    return redirect(url_for('profile'))


# ============================================================
# 🚨 VULN #7 : IDOR sur les commandes
# ============================================================
@app.route('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    # 🚨 VULNÉRABLE : aucune vérification de propriété
    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(order.to_dict())


@app.route('/api/users/<int:user_id>')
@login_required
def get_user(user_id):
    # 🚨 VULNÉRABLE : exposition de données d'autres utilisateurs
    user = User.query.get(user_id)
    if not user:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(user.to_dict())


# ============================================================
# 🚨 VULN #9 : SSTI (Server-Side Template Injection)
# ============================================================
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # 🚨 VULNÉRABLE : template rendu dynamiquement avec input utilisateur
    template_str = f"<h1>Hello {name}!</h1>"
    template = Template(template_str)
    return template.render()


# ============================================================
# 🚨 VULN #10 : PATH TRAVERSAL
# ============================================================
@app.route('/download')
def download():
    filename = request.args.get('file', '')
    # 🚨 VULNÉRABLE : pas de validation du chemin
    filepath = os.path.join('uploads', filename)
    try:
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        return f"Error: {str(e)}", 404


# ============================================================
# 🚨 VULN #11 : COMMAND INJECTION
# ============================================================
@app.route('/ping', methods=['GET', 'POST'])
def ping():
    result = None
    if request.method == 'POST':
        host = request.form.get('host', '')
        # 🚨 VULNÉRABLE : injection de commande via shell=True
        try:
            result = subprocess.check_output(
                f"ping -c 1 {host}",
                shell=True,
                stderr=subprocess.STDOUT,
                timeout=5
            ).decode()
        except Exception as e:
            result = f"Error: {str(e)}"
    return render_template('ping.html', result=result)


# ============================================================
# 🚨 VULN : Admin panel sans contrôle suffisant
# ============================================================
@app.route('/admin')
@login_required
def admin():
    # 🚨 VULNÉRABLE : vérification facilement contournable via mass assignment
    if not current_user.is_admin:
        abort(403)
    users = User.query.all()
    return render_template('admin.html', users=users)


# ============================================================
# Endpoint debug (🚨 ne devrait pas exister en prod)
# ============================================================
@app.route('/debug/config')
def debug_config():
    # 🚨 VULNÉRABLE : exposition de configuration
    return jsonify({
        'SECRET_KEY': app.config.get('SECRET_KEY'),
        'DATABASE_URI': app.config.get('SQLALCHEMY_DATABASE_URI'),
        'DEBUG': app.debug
    })


if __name__ == '__main__':
    # 🚨 VULNÉRABLE : debug=True en production exposerait la console Werkzeug
    app.run(host='0.0.0.0', port=5000, debug=True)
