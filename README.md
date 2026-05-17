# SECE843 — Security By Design

Support pédagogique du cours **SECE843 - Security By Design** (Master).
Le dépôt contient une application Flask volontairement vulnérable, sa version
remédiée, les supports de cours et une présentation Marp.

> ⚠️ **Usage strictement pédagogique.** L'application `vulnpyapp/` contient des
> vulnérabilités intentionnelles. Ne jamais la déployer sur Internet ou sur un
> réseau de production.

## Structure du dépôt

```
.
├── vulnpyapp/              # App Flask v1.0 — volontairement vulnérable (15 failles)
├── vulnpyapp_remediated/   # App Flask v2.0 — version sécurisée jumelle
├── docs/
│   ├── guide_correction.md # Guide pas-à-pas : pour chaque vuln, exploit + correctif
│   ├── presentation.md     # Présentation Marp du cours
│   └── presentation.pdf    # Version PDF générée
├── seance1.md              # Cours magistral séance 1 (Fondamentaux + Injections)
├── seance2.md              # Cours magistral séance 2 (Auth, AuthZ, SDLC)
└── CLAUDE.md               # Guide de contribution (cohérence inter-composants)
```

Les quatre artefacts pédagogiques (app vulnérable, app remédiée, guide,
séances) sont **maintenus en cohérence** : la numérotation `#1..#15` des
vulnérabilités est identique partout, et tout extrait de code cité dans la
doc correspond mot pour mot au code en place.

## Les 15 vulnérabilités du support

| # | Vulnérabilité | CWE | Route |
|---|---------------|-----|-------|
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

Dans le code : marqueurs `🚨 VULN #N` (app vulnérable) ↔ `✅ FIX #N` (app remédiée).

## Démarrage rapide

> Les deux applications partagent le port `5000` — **ne jamais les lancer simultanément**.

### Application vulnérable

```bash
cd vulnpyapp
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python init_db.py
python app.py                  # http://localhost:5000
# ou
docker-compose up --build
```

### Application remédiée

```bash
cd vulnpyapp_remediated
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python init_db.py
python app.py                  # 127.0.0.1:5000 (debug désactivé)

# Tests sécurité + non-régression (≥ 80 % de couverture imposée)
pytest tests/ -v --cov=. --cov-fail-under=80
```

### Comptes de test (communs aux deux apps)

| Email | Mot de passe | Rôle |
|-------|--------------|------|
| `admin@vulnpyapp.local` | `Admin123!` | admin |
| `alice@vulnpyapp.local` | `Alice123!` | user |
| `bob@vulnpyapp.local`   | `Bobby123!` | user |

## Supports de cours

- **`seance1.md`** — Fondamentaux (CIA, RGPD, OWASP Top 10), injections SQL,
  XSS, protections navigateur (SOP / CORS / CSP).
- **`seance2.md`** — CSRF, IDOR, Mass Assignment, authentification sécurisée
  (Argon2, MFA, reset), sessions, headers, rate limiting, SDLC sécurisé,
  OWASP API Top 10.
- **`docs/guide_correction.md`** — pour chaque vulnérabilité : localisation,
  code vulnérable, exploitation, correctif et vérification.
- **`docs/presentation.md`** — synthèse au format Marp (38 slides).

### Régénérer la présentation

```bash
npx --yes @marp-team/marp-cli@latest docs/presentation.md --pdf
# ou : --html / --pptx
```

## Exercices et calendrier

| Exercice | Description | Deadline | Poids |
|----------|-------------|----------|-------|
| 1.A | Cartographie + analyse RGPD (lab guidé) | Séance 1 | — |
| 1.B | CTF SQLi & XSS (binôme) | S1 + 7 j | 20 % |
| 1.C | Quiz fondamentaux (QCM) | Fin séance 1 | 10 % |
| 2.A | Revue de code en séance (individuel) | Séance 2 | 15 % |
| 2.B | Audit Bandit/Safety + tests pytest | S2 + 7 j | 25 % |
| 3   | Projet : sécurisation d'une app Django | S3 + 14 j | 30 % |

Détail complet dans `seance1.md` et `seance2.md`.

## Audit statique (CI)

```bash
cd vulnpyapp_remediated
bandit -r . -x ./tests --severity-level medium --confidence-level medium
safety check
```

## Licence

MIT — usage pédagogique uniquement.
