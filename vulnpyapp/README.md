# VulnPyApp 🐍🔓

Application web Flask **volontairement vulnérable** destinée à la formation
**Security By Design** (Master).

## ⚠️ AVERTISSEMENT

Cette application contient des vulnérabilités intentionnelles à des fins
pédagogiques. **NE JAMAIS** la déployer sur Internet ou un réseau de production.
Utilisation exclusive en environnement isolé (Docker, VM, localhost).

## Vulnérabilités présentes

| # | Vulnérabilité | CWE | Route concernée |
|---|---------------|-----|-----------------|
| 1 | SQL Injection (login) | CWE-89 | `/login` |
| 2 | SQL Injection (search) | CWE-89 | `/search` |
| 3 | XSS Reflected | CWE-79 | `/search` |
| 4 | XSS Stored | CWE-79 | `/comments` |
| 5 | XSS DOM-based | CWE-79 | `/profile` |
| 6 | CSRF | CWE-352 | `/profile/update` |
| 7 | IDOR | CWE-639 | `/api/orders/<id>` |
| 8 | Mass Assignment | CWE-915 | `/register` |
| 9 | SSTI (Jinja2) | CWE-1336 | `/hello` |
| 10 | Path Traversal | CWE-22 | `/download` |
| 11 | Command Injection | CWE-78 | `/ping` |
| 12 | Hashage faible (MD5) | CWE-327 | login system |
| 13 | Cookies non sécurisés | CWE-614 | sessions |
| 14 | Absence de rate limiting | CWE-307 | `/login` |
| 15 | Headers de sécurité absents | CWE-693 | global |

## Installation

### Avec Docker (recommandé)

```bash
git clone <votre-repo>/vulnpyapp.git
cd vulnpyapp
docker-compose up --build
```

Application accessible sur http://localhost:5000

### Installation locale

```bash
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows
pip install -r requirements.txt
python init_db.py
python app.py
```

## Comptes de test

| Email | Mot de passe | Rôle |
|-------|--------------|------|
| admin@vulnpyapp.local | Admin123! | admin |
| alice@vulnpyapp.local | Alice123! | user |
| bob@vulnpyapp.local | Bobby123! | user |

## Utilisation pédagogique

1. **Séance 1** : exploiter SQLi et XSS (voir `solutions/exploit_sqli.py`, `exploit_xss.py`)
2. **Séance 2** : audit complet + remédiation (projet final)

Les scripts de `solutions/` sont à destination de l'enseignant uniquement.

## Licence

MIT - Usage pédagogique uniquement.
