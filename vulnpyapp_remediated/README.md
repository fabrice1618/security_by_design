# VulnPyApp v2.0 — Branche `remediated`

Version sécurisée complète de **VulnPyApp**, avec toutes les vulnérabilités
intentionnelles de la v1.0 corrigées en appliquant les principes
**Security By Design**.

Voir `CHANGELOG_SECURITY.md` pour la liste exhaustive des correctifs.

## Installation

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python init_db.py
python app.py
```

## Tests

```bash
pytest tests/ -v --cov=. --cov-fail-under=80
```

Tous les tests `test_security.py` et `test_regression.py` doivent passer.

## Docker

```bash
docker-compose up --build
```

## Comptes de test

| Email | Mot de passe | Rôle |
|-------|--------------|------|
| admin@vulnpyapp.local | Admin123! | admin |
| alice@vulnpyapp.local | Alice123! | user |
| bob@vulnpyapp.local | Bobby123! | user |
