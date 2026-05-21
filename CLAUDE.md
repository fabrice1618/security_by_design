# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Contexte du projet

Support pédagogique pour le cours **Security By Design** (Master). Le dépôt contient une application Flask volontairement vulnérable, sa version remédiée, et les supports de cours associés. Tout le contenu est en français.

## Structure des composants

Le dépôt est constitué de **quatre artefacts liés** qui doivent rester cohérents entre eux :

1. **`vulnpyapp/`** — Application Flask **volontairement vulnérable** (v1.0). 15 vulnérabilités numérotées (#1 à #15) marquées dans le code par des commentaires `🚨 VULN #N`. Le `README.md` liste la correspondance vulnérabilité ↔ route ↔ CWE.
2. **`vulnpyapp_remediated/`** — Version **sécurisée** (v2.0) de la même application. Chaque correctif est marqué `✅ FIX #N` et documenté dans `CHANGELOG_SECURITY.md`. Architecture refactorée : `create_app()` factory, `extensions.py`, `schemas.py` (Marshmallow), `security.py`, `logging_config.py`.
3. **`docs/guide_correction.md`** — Guide pas-à-pas (étudiant/enseignant) qui explique chaque vulnérabilité et son correctif, avec des extraits de code des deux versions.
4. **`seance1.md`, `seance2.md`** — Cours magistraux qui référencent les routes vulnérables et leurs exploitations.

### ⚠️ Règle de cohérence transversale

**Les quatre parties du projet doivent évoluer ensemble.** Toute modification d'un élément implique généralement la mise à jour des autres :

- Ajout/suppression/renumérotation d'une vulnérabilité dans `vulnpyapp/app.py` → mettre à jour
  - `vulnpyapp/README.md` (tableau des vulnérabilités)
  - `vulnpyapp/solutions/exploit_*.py` (script d'exploitation correspondant)
  - `vulnpyapp_remediated/app.py` (correctif `✅ FIX #N`)
  - `vulnpyapp_remediated/CHANGELOG_SECURITY.md` (entrée du tableau)
  - `vulnpyapp_remediated/tests/test_security.py` (test de non-régression)
  - `docs/guide_correction.md` (section `CORRECTION #N`)
  - `seance1.md` / `seance2.md` si la vulnérabilité est citée

- Modification d'une route, d'un champ de formulaire ou d'un nom de paramètre → vérifier les exploits dans `vulnpyapp/solutions/`, les tests `test_security.py` / `test_regression.py`, et les extraits cités dans `docs/guide_correction.md` et les séances.

- Modification du schéma de données (`models.py`) ou des comptes de test dans `init_db.py` → synchroniser entre `vulnpyapp/` et `vulnpyapp_remediated/`, et mettre à jour les deux `README.md` si les identifiants changent.

- Numérotation `#N` des vulnérabilités/correctifs : doit être **identique** dans les deux applications, dans les tableaux des README et CHANGELOG, et dans `guide_correction.md`.

Avant de clore une modification, relire les fichiers liés et vérifier la cohérence des extraits de code copiés dans la doc (les blocs cités dans `docs/guide_correction.md` doivent correspondre **mot pour mot** au code actuel).

## Commandes de développement

### Application vulnérable (`vulnpyapp/`)

```bash
cd vulnpyapp
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python init_db.py          # (ré)initialise instance/vulnpyapp.db avec données de test
python app.py              # lance sur http://localhost:5000 (debug=True intentionnel)
# ou
docker-compose up --build
pytest tests/ -v
```

### Application remédiée (`vulnpyapp_remediated/`)

```bash
cd vulnpyapp_remediated
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python init_db.py
python app.py              # 127.0.0.1:5000, debug désactivé sauf FLASK_DEBUG=1

# Tests : sécurité (FIX #1..#15) + non-régression. Le README impose 80% de couverture.
pytest tests/ -v --cov=. --cov-fail-under=80

# Test ciblé
pytest tests/test_security.py::TestSQLInjection::test_sqli_login_bypass_blocked -v

# Audit statique / dépendances (CI exécute ces étapes via .github/workflows/security.yml)
bandit -r . -x ./tests --severity-level medium --confidence-level medium
safety check -r requirements.txt  # Safety 2.x épinglé ; Safety 3.x : safety scan
```

### Exploits pédagogiques

Les scripts `vulnpyapp/solutions/exploit_*.py` ciblent l'app vulnérable lancée localement sur le port 5000. Ils sont à usage **enseignant** et doivent rester fonctionnels après toute modification de l'app vulnérable correspondante.

## Architecture

### `vulnpyapp/` (vulnérable, monofichier)

- `app.py` : toutes les routes dans un seul fichier, vulnérabilités explicitement annotées. Tient lieu de référence pour la version remédiée — l'ordre et la numérotation des vulnérabilités doivent être préservés.
- `config.py` : config intentionnellement faible (SECRET_KEY par défaut, cookies non sécurisés).
- `models.py` : SQLAlchemy (User, Product, Order, Comment). Le hash de mot de passe utilise MD5 (vuln #12).

### `vulnpyapp_remediated/` (sécurisé, modulaire)

Application factory pattern :
- `app.py` :: `create_app()` initialise extensions, CSP/HSTS via Talisman, error handlers.
- `extensions.py` : instances partagées (`db`, `login_manager`, `csrf`, `limiter`, `talisman`) — évite les imports circulaires.
- `schemas.py` : validation Marshmallow (allowlist explicite contre mass assignment).
- `security.py` : helpers (`sanitize_html` via Bleach, `admin_required`, `safe_path`, `is_safe_host`).
- `logging_config.py` : logs structurés.
- `models.py` : bcrypt (cost 12), méthodes `is_locked()`, `to_safe_dict()`.
- Templates dans `templates/errors/` pour les pages d'erreur génériques (sans fuite d'info).

Chaque correctif est tagué `✅ FIX #N` en commentaire de route, en miroir des `🚨 VULN #N` de l'app vulnérable.

### Tests

- `vulnpyapp/tests/test_security.py` : démontre que les vulnérabilités **sont** exploitables (les assertions vérifient le succès de l'attaque).
- `vulnpyapp_remediated/tests/test_security.py` : démontre que chaque attaque **est bloquée** (codes 400/401/403/429, absence de payload réfléchi, etc.). `test_regression.py` vérifie que les fonctionnalités légitimes marchent toujours.

## Conventions

- Tout le texte utilisateur, commentaires de code et documentation sont en **français** — préserver la langue lors d'éditions.
- Les marqueurs `🚨 VULN #N` (vulnérable) et `✅ FIX #N` (remédié) sont **structurels** : ils servent au repérage par les étudiants et à la cohérence inter-fichiers. Ne pas les supprimer ni renuméroter sans propager partout.
- Comptes de test communs aux deux apps : `admin@vulnpyapp.local / Admin123!`, `alice@... / Alice123!`, `bob@... / Bobby123!`. Si un mot de passe change, mettre à jour les deux `init_db.py` et les deux `README.md`.
- Les deux applications partagent le port `5000` ; ne jamais les lancer simultanément.
