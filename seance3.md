# SÉANCE 3 : Projet de sécurisation d'application (2 semaines)

**Pondération : 30% de la note finale**

---

## Objectifs du projet

À l'issue de ce projet, vous serez capables de :

- **Analyser** une application vulnérable et identifier toutes les failles de sécurité
- **Auditer** le code avec des outils statiques (bandit, safety) et manuellement
- **Rédiger** un rapport d'audit professionnel avec priorités de remédiation
- **Remédier** aux vulnérabilités en appliquant les principes **Security by Design**
- **Tester** que les corrections fonctionnent et ne cassent pas les fonctionnalités existantes
- **Justifier** vos choix architecturaux en termes de sécurité, performance et maintenabilité

---

## Contexte du projet

Vous recevrez une **application web vulnérable** (Flask) contenant volontairement plusieurs catégories de failles :

- Injections (SQL, SSTI, commandes système)
- Vulnérabilités d'accès (authentification, IDOR, CSRF)
- Gestion des données sensibles (hachage faible, cookies non sécurisés)
- Protections manquantes (CSP, rate limiting, logging)

Votre mission est **triple** :

1. **Auditer** l'application : identifier et documenter les vulnérabilités
2. **Remédier** : écrire du code sécurisé basé sur les bonnes pratiques
3. **Valider** : tester que tout fonctionne et que les risques ont disparu

---

## Structure du projet

### Périmètre et contraintes

**Ce qui est dans le scope :**

- Identification des vulnérabilités dans le code fourni
- Corrections de code avec tests automatisés (pytest, etc.)
- Rapport d'audit technique et recommandations
- Démonstration de l'exploit sur l'app vulnérable ET du blocage sur l'app remédiée

**Ce qui est HORS scope :**

- Architecture complète rewrite (adapter le code existant, ne pas réécrire)
- Performance optimization (sauf si lié à une vulnérabilité, ex. ReDoS)
- Nouvelles fonctionnalités
- Déploiement en production (local ou Docker suffisent)

### Livrables attendus

```
projet_flask_secured/
├── app_vulnerable/             # Code vulnérable (fourni, analysé)
│   ├── app.py
│   ├── models.py
│   ├── requirements.txt
│   └── tests/
├── app_remediated/             # Code sécurisé (votre travail)
│   ├── app.py                  # Corrections annotées avec ✅ FIX #N
│   ├── models.py
│   ├── security.py             # Helpers de sécurité (sanitize, is_safe_host, etc.)
│   ├── requirements.txt
│   └── tests/
│       ├── test_security.py    # Tests que les exploits sont bloqués
│       └── test_regression.py  # Tests que les fonctionnalités marchent
├── rapport_audit.md            # Document principal (voir structure ci-dessous)
├── exploits/
│   ├── exploit_sqli.py         # Preuve de vulnérabilité sur l'app originale
│   ├── exploit_xss.py
│   └── ...
└── README.md                   # Instructions pour démarrer les deux versions
```

---

## Travail attendu

### PARTIE A — Audit outillé et manuel (40 pts)

#### Sous-partie A1 : Scan statique (10 pts)

Exécuter les outils de sécurité et documenter les résultats :

```bash
# Dans le dossier app_vulnerable/
bandit -r . -x ./tests --severity-level medium --confidence-level medium
safety check --json  # Safety 2.x ; Safety 3.x : safety scan
```

**Livrable A1 :**
- Fichier `audit_bandit.txt` et `audit_safety.json`
- Tableau récapitulatif : nombre d'issues par sévérité

#### Sous-partie A2 : Audit manuel (15 pts)

Lire le code et identifier manuellement les vulnérabilités **en fonction des 15 patterns étudiés en cours**:

1. SQL Injection
2. XSS (réfléchie, stockée, DOM)
3. CSRF
4. IDOR
5. Mass Assignment
6. SSTI
7. Path Traversal
8. Command Injection
9. Hachage faible
10. Cookies non sécurisés
11. Rate limiting absent
12. Headers de sécurité manquants
13. (+ tout autre pattern aperçu)

**Format du rapport d'audit manuel :**

```markdown
# Audit de Sécurité — app_vulnerable

## Vulnérabilité #1 — SQL Injection (login)

**Localisation :** app.py, ligne 45, fonction `login()`

**Sévérité :** 🔴 Critique (CVSS 9.8)

**Code vulnérable :**
```python
query = f"SELECT * FROM users WHERE email='{email}' AND password_hash='{pwd_hash}'"
```

**Exploitation possible :**
```
Email : admin@example.com' --
Password : anything
→ Requête : SELECT * FROM users WHERE email='admin@example.com' --' AND password_hash='...'
→ Résultat : contourne le contrôle de mot de passe
```

**Impact :** Accès administrateur sans authentification valide

**Correction recommandée :** Utiliser un ORM (SQLAlchemy) ou prepared statements

---

[Répéter pour chaque vulnérabilité identifiée]
```

#### Sous-partie A3 : Checklist OWASP (15 pts)

Compléter la checklist OWASP Web Top 10 (2021) appliquée à l'app :

```markdown
# Checklist OWASP Top 10 — app_vulnerable

| Risque | Testé | Présent | Évidence | Remédiation |
|--------|-------|---------|----------|-------------|
| A01:2021 – Broken Access Control | ✅ | ✅ | IDOR /api/users/<id> | Vérifier current_user.id |
| A02:2021 – Cryptographic Failures | ✅ | ✅ | MD5 pour mots de passe | Utiliser bcrypt |
| A03:2021 – Injection | ✅ | ✅ | SQLi login | Prepared statements |
| A04:2021 – Insecure Design | ✅ | ❌ | — | — |
| A05:2021 – Security Misconfiguration | ✅ | ✅ | DEBUG=True en prod | DEBUG=False + headers |
| ... | | | | |
```

---

### PARTIE B — Remédiation et tests (40 pts)

Écrire le code sécurisé dans `app_remediated/` avec **chaque correction annotée `✅ FIX #N`**.

#### Sous-partie B1 : Correctifs de code (25 pts)

Pour chaque vulnérabilité identifiée :

1. **Localiser** le code vulnérable
2. **Annoter** le code original avec un commentaire `🚨 VULN #N` (référence)
3. **Implémenter** la correction
4. **Annoter** la correction avec un commentaire `✅ FIX #N`
5. **Ajouter** une brève explication du pourquoi

**Exemple :**

```python
# 🚨 VULN #1 : SQL Injection (login)
# query = f"SELECT * FROM users WHERE email='{email}'"

# ✅ FIX #1 : Utiliser l'ORM SQLAlchemy (requête paramétrée)
user = User.query.filter_by(email=email).first()
if user and user.check_password(password):
    login_user(user)
```

#### Sous-partie B2 : Tests de sécurité (15 pts)

Écrire des tests pytest pour **confirmer que chaque attaque est bloquée** :

```python
# tests/test_security.py

class TestSQLInjection:
    def test_login_injection_blocked(self, client):
        """Vérifier que l'injection SQL du login est bloquée"""
        response = client.post('/login', data={
            'email': "admin@example.com' --",
            'password': 'anything'
        })
        assert response.status_code == 401  # Authentication failed
        assert 'Invalid credentials' in response.data.decode()

class TestXSS:
    def test_reflected_xss_escaped(self, client):
        """Vérifier que le XSS réfléchi est échappé"""
        response = client.get('/search?q=<script>alert(1)</script>')
        assert '<script>' not in response.data.decode()
        assert '&lt;script&gt;' in response.data.decode()

class TestIDOR:
    def test_idor_users_api_blocked(self, client, auth_user):
        """Vérifier que IDOR est bloqué : un user ne peut pas accéder aux données d'un autre"""
        # Connexion comme user_id=2
        client.post('/login', data={'email': 'alice@vulnpyapp.local', 'password': 'Alice123!'})
        
        # Tentative d'accès aux données du user_id=1
        response = client.get('/api/users/1')
        assert response.status_code == 403  # Forbidden
```

---

### PARTIE C — Rapport d'audit et justification (20 pts)

Document unique `rapport_audit.md` (4–6 pages minimum) :

#### Section 1 : Résumé exécutif (2 pts)

```markdown
# Rapport d'Audit de Sécurité — Application Flask

**Date :** [Date]
**Auditeur(s) :** [Noms]
**Application :** app_vulnerable
**Durée de l'audit :** [Nombre d'heures]

## Résumé

L'audit a identifié **N vulnérabilités**, dont **X critiques**, **Y élevées** et **Z moyennes**.

**Risque global :** 🔴 CRITIQUE — exploitation triviale possible sans authentification

**Recommandation immédiate :** Arrêter la production et remédier aux vulnérabilités critiques avant redéploiement.
```

#### Section 2 : Méthodologie (2 pts)

```markdown
## Méthodologie

**Périmètre :** Code Python, configuration Flask, templates, BDD

**Outils utilisés :**
- Bandit (scan statique Python)
- Safety 2.x ou Safety 3.x (`safety scan`) / pip-audit (audit dépendances)
- Analyse manuelle du code (16 heures)
- Tests d'exploitation sur app vulnérable

**Standards appliqués :**
- OWASP Top 10 (2021)
- CVSS v3.1 (notation de gravité)
- CWE (Common Weakness Enumeration)

**Hypothèses de sécurité :**
- Attaquant non authentifié (externe)
- Accès réseau à l'app depuis internet
- Serveur en HTTP non chiffré (évaluation du code, pas du transport)
```

#### Section 3 : Résultats détaillés (8 pts)

```markdown
## Résultats

### Vulnérabilités par sévérité

| Sévérité | Nombre | Exemples |
|----------|--------|----------|
| 🔴 Critique (CVSS 9–10) | 2 | SQLi, Command Injection |
| 🟠 Élevée (CVSS 7–8.9) | 3 | SSTI, Weak Hash |
| 🟡 Moyenne (CVSS 4–6.9) | 2 | Missing Headers |
| 🟢 Faible (CVSS 0–3.9) | 1 | Info Disclosure |

### Détail par vulnérabilité

[Reprendre le format de Partie A2 : localisation, code vulnérable, exploitation, impact, correction]
```

#### Section 4 : Chaîne de remédiation (4 pts)

```markdown
## Plan de remédiation

### Phase 1 : Urgente (jour 1)
- [ ] Fix #1 : SQL Injection login
- [ ] Fix #11 : Command Injection ping
→ Prévient RCE, accès administrateur

### Phase 2 : Haute priorité (semaine 1)
- [ ] Fix #3, #4, #5 : XSS
- [ ] Fix #7 : IDOR
→ Prévient vol de données utilisateur

### Phase 3 : Moyen terme (semaine 2)
- [ ] Fix #9 : Weak Hash
- [ ] Fix #15 : Security Headers
→ Améliore posture de sécurité globale

### Coût estimé
- Dev : 16 heures
- QA : 8 heures
- Redéploiement : 2 heures
```

#### Section 5 : Justification architecturale (4 pts)

```markdown
## Choix architecturaux

### Pourquoi ORM plutôt que SQL raw
- Séparation données / code
- Protection native contre SQLi
- Maintenance future plus facile

### Pourquoi bcrypt pour les mots de passe
- Fonction de coût configurable (slowing down bruteforce)
- Salt unique par password
- Standard NIST recommandé

### Pourquoi Flask-Talisman pour les headers
- Centralisé : une seule ligne pour tous les headers
- Maintenable : config explicite
- Non-invasif : n'affecte pas le code métier

### Contraintes acceptées
- Performance : bcrypt est lent (intentionnellement) → limiter à login uniquement
- Compatibilité : HSTS peut bloquer certains clients très anciens → documenter
```

---

## Critères d'évaluation

### Audit (PARTIE A)

| Critère | Points | Détail |
|---------|--------|--------|
| Complétude | /10 | Tous les patterns de cours trouvés ? |
| Justesse | /15 | L'analyse est-elle correcte (pas de faux positifs) ? |
| OWASP checklist | /15 | Checklist remplie précisément |
| **Total A** | **/40** | |

### Remédiation (PARTIE B)

| Critère | Points | Détail |
|---------|--------|--------|
| Code sécurisé | /15 | Corrections appliquées, code lisible, annoté |
| Tests | /15 | Tests couvrent les exploits, ≥80% pass rate |
| Pas de régression | /10 | Fonctionnalités existantes toujours OK |
| **Total B** | **/40** | |

### Rapport (PARTIE C)

| Critère | Points | Détail |
|---------|--------|--------|
| Clarté & structure | /5 | Facile à lire, bien organisé |
| Complétude | /5 | Toutes les sections présentes |
| Justification | /10 | Choix architecturaux bien argumentés |
| **Total C** | **/20** | |

### Bonus

```
Bonus                                | Points | Condition
-------------------------------------|--------|----------------------------------
Rapport au format PDF professionnel  | +3     | pandoc, styles, mise en page
Pipeline CI/CD (GitHub Actions)      | +5     | bandit + pytest + safety auto
Démonstration vidéo (5 min)          | +3     | Exploit → Remédiation, commenté
```

---

## Ressources

### Documentation

- [Flask Security](https://flask.palletsprojects.com/en/2.3.x/security/)
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [CWE/CVSS](https://cwe.mitre.org/)

### Outils

- **Bandit** : `pip install bandit`
- **Safety** : `pip install safety`
- **SQLMap** : SQL injection tester (référence uniquement)
- **Pytest** : `pip install pytest pytest-cov`

### Code d'exemple

Les fichiers `docs/guide_correction.md` du cours contiennent des solutions complètes pour les 15 vulnérabilités — utiliser comme référence, pas comme copie.

---

## Conditions de rendu

**Format :**
- Archive ZIP : `<NOM1>_<NOM2>_seance3.zip`
- Contient : code + rapport + exploits

**Deadline :** Fin de semaine 14 du semestre (à confirmer par l'enseignant)

**Plateforme :** Moodle

**Contrôle plagiaire :**
- Moss/JPLAG sur le code Python
- Turnitin sur le rapport
- Présentations en cas de doute

---

## Questions fréquentes

**Q : Faut-il réécrire toute l'application ?**
A : Non. Adapter le code existant. Si >30% du code est réécrit sans justification sécurité, c'est une régression.

**Q : Les tests doivent-ils être parfaits ?**
A : Minimum 80% de couverture. Les tests critiques (sécurité) passent, les tests flaky sont acceptés s'ils sont documentés.

**Q : Peut-on utiliser des libraries tiers pour les correctifs ?**
A : Oui, c'est même recommandé (bcrypt, Bleach, etc.). Documenter l'ajout dans `requirements.txt`.

**Q : La performance peut-elle pâtir des corrections ?**
A : Oui, c'est normal (ex. bcrypt lent). Documenter et justifier. Priorité : sécurité > performance.

**Q : Où trouver les solutions de cours ?**
A : `docs/guide_correction.md`. Ne pas copier le code, l'adapter au contexte du projet.
