# VulnPyApp — Fiches d'exercice
## SECE843 - Security By Design

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

#### Challenge 3 — IDOR & Information Disclosure *(20 pts)*

**Contexte :** La route `/api/users/<id>` expose les données des utilisateurs sans vérifier que le demandeur est le propriétaire du compte.

**Objectif :** Énumérer les utilisateurs enregistrés et identifier les comptes administrateurs via itération d'ID.

**Principe :**
```
/api/users/1   → { "id": 1, "email": "admin@...", "is_admin": true, ... }
/api/users/2   → { "id": 2, "email": "alice@...",  "is_admin": false, ... }
/api/users/3   → { "id": 3, "email": "bob@...",    "is_admin": false, ... }

→ En itérant les ID, vous pouvez cartographier tous les utilisateurs
  et leurs rôles (admin ou non).
```

**Travail attendu :**
1. Script Python (`exploit_idor_users.py`) automatisant l'extraction
2. Fichier `users_dump.json` listant tous les utilisateurs avec leur rôle
3. Capture d'écran prouvant l'accès non autorisé aux données d'un autre utilisateur
4. Analyse d'impact : chaîne de compromission possible avec ces informations

**Bonus :** Proposer une correction empêchant cette fuite d'information

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
│   ├── exploit_idor_users.py      # Challenge 3
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
| 3 IDOR / Info Disclosure | ✅/❌ | ✅/❌ | /20 |
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
│  Challenge 3 - IDOR / Info Disclosure │ /20    │ Script + analyse d'impact │
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
│  Correction IDOR complète   │ +3     │                      │
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
└───────────────────────────────────────┴────────────┴────────────┘

Format de rendu : Archive ZIP nommée <NOM1>_<NOM2>_<exercice>.zip
Plateforme     : Moodle (lien fourni par l'enseignant)
Contact        : securite@institution.fr
```
