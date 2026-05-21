# Glossaire des acronymes — Security By Design

Lexique des termes et acronymes utilisés dans les documents du cours.

---

## 🔒 Sécurité générale

| Acronyme | Sens | Description |
|----------|------|-------------|
| **CIA** | Confidentialité, Intégrité, Disponibilité | Triade fondamentale de la sécurité de l'information |
| **SDLC** | Software Development Life Cycle | Cycle de vie du développement logiciel sécurisé |
| **SAST** | Static Application Security Testing | Test de sécurité par analyse statique du code |
| **SCA** | Software Composition Analysis | Analyse des vulnérabilités dans les dépendances logicielles |
| **CVE** | Common Vulnerabilities and Exposures | Identifiant standardisé des vulnérabilités publiques |
| **CVSS** | Common Vulnerability Scoring System | Système de notation de la gravité des vulnérabilités (0-10) |
| **CWE** | Common Weakness Enumeration | Classification des faiblesses de sécurité logicielles |
| **OWASP** | Open Worldwide Application Security Project | Organisation de référence pour la sécurité applicative |
| **CTF** | Capture The Flag | Compétition ou exercice de sécurité (exploit + correction) |

---

## 💉 Vulnérabilités web

| Acronyme | Sens | Description |
|----------|------|-------------|
| **SQLi** | SQL Injection | Injection de commandes SQL malveillantes (CWE-89) |
| **XSS** | Cross-Site Scripting | Injection de JavaScript exécuté dans le navigateur (CWE-79) |
| **CSRF** | Cross-Site Request Forgery | Forgerie de requête inter-site (CWE-352) |
| **IDOR** | Insecure Direct Object Reference | Accès non autorisé via manipulation d'identifiants (CWE-639) |
| **BOLA** | Broken Object Level Authorization | Synonyme moderne d'IDOR |
| **SSTI** | Server-Side Template Injection | Injection dans un moteur de templates côté serveur (CWE-1336) |
| **SSRF** | Server-Side Request Forgery | Forcer le serveur à faire une requête pour vous (A10:2021) |
| **DDoS** | Distributed Denial of Service | Attaque par déni de service distribué |
| **PII** | Personally Identifiable Information | Données personnelles identifiantes |

---

## 🔐 Authentification et contrôle d'accès

| Acronyme | Sens | Description |
|----------|------|-------------|
| **MFA** | Multi-Factor Authentication | Authentification multi-facteur (password + OTP/biométrie) |
| **TOTP** | Time-based One-Time Password | Mot de passe unique basé sur le temps (Google Authenticator) |
| **FIDO2** | Fast Identity Online 2 | Standard d'authentification sécurisée sans mot de passe |
| **WebAuthn** | Web Authentication | API navigateur pour authentification FIDO2/USB |
| **JWT** | JSON Web Token | Token signé pour authentification stateless |
| **RBAC** | Role-Based Access Control | Contrôle d'accès par rôles (admin, user, etc.) |
| **ABAC** | Attribute-Based Access Control | Contrôle d'accès par attributs (contexte, ressource, utilisateur) |
| **SoD** | Séparation des responsabilités | Principle of least privilege — droits minimaux nécessaires |
| **OAuth** | Open Authorization | Standard d'authentification déléguée tiers (Google, GitHub) |

---

## 🔑 Cryptographie et stockage

| Acronyme | Sens | Description |
|----------|------|-------------|
| **TLS** | Transport Layer Security | Protocole de chiffrement en transit (HTTPS) |
| **HTTPS** | HyperText Transfer Protocol Secure | HTTP sécurisé par TLS |
| **AES** | Advanced Encryption Standard | Algorithme de chiffrement symétrique standard (128/256 bits) |
| **SHA** | Secure Hash Algorithm | Fonction de hachage sécurisée (SHA-256, SHA-512) |
| **MD5** | Message Digest Algorithm 5 | ⚠️ Fonction de hachage **obsolète** — ne JAMAIS utiliser |
| **HMAC** | Hash-based Message Authentication Code | Code d'authentification basé sur un hash |
| **BCrypt** | Adaptive Password Hashing | Fonction de hachage de mots de passe (cost factor) |
| **Argon2** | Memory-hard Key Derivation Function | Fonction de dérivation de clé résistante au GPU (recommandée) |
| **PBKDF2** | Password-Based Key Derivation Function 2 | Fonction de dérivation de clé itérative |
| **TDE** | Transparent Data Encryption | Chiffrement transparent des données au repos |
| **HSM** | Hardware Security Module | Module matériel sécurisé pour stocker les clés |
| **KMS** | Key Management Service | Service cloud de gestion centralisée des clés |
| **Nonce** | Number Used Once | Valeur aléatoire unique pour chaque utilisation |
| **RC4** | Rivest Cipher 4 | ⚠️ Algorithme de chiffrement **obsolète** |
| **ECB** | Electronic Codebook | ⚠️ Mode de chiffrement **dangereux** (patterns visibles) |

---

## 🌐 Protocoles et standards web

| Acronyme | Sens | Description |
|----------|------|-------------|
| **HTTP** | HyperText Transfer Protocol | Protocole de communication web (sans chiffrement) |
| **HTML** | HyperText Markup Language | Langage de balisage pour pages web |
| **URL** | Uniform Resource Locator | Adresse d'une ressource sur le web |
| **JSON** | JavaScript Object Notation | Format structuré d'échange de données |
| **XML** | eXtensible Markup Language | Format hiérarchique d'échange de données |
| **AJAX** | Asynchronous JavaScript and XML | Requêtes asynchrones côté client |
| **API** | Application Programming Interface | Interface pour la communication entre programmes |
| **REST** | Representational State Transfer | Style architectural pour APIs web |
| **LDAP** | Lightweight Directory Access Protocol | Protocole d'annuaire (authentification centralisée) |
| **SQL** | Structured Query Language | Langage d'interrogation de bases de données |
| **DOM** | Document Object Model | Représentation hiérarchique du contenu HTML |
| **CORS** | Cross-Origin Resource Sharing | Mécanisme pour autoriser requêtes cross-origin |
| **SOP** | Same-Origin Policy | Politique de sécurité : isolation entre origines différentes |
| **CSP** | Content Security Policy | En-tête HTTP définissant les sources de contenu autorisées |
| **HSTS** | HTTP Strict Transport Security | En-tête forcant le navigateur à utiliser HTTPS |

---

## 🏗️ Frameworks et outils Python

| Acronyme | Sens | Description |
|----------|------|-------------|
| **ORM** | Object-Relational Mapping | Abstraction orientée objet sur base de données |
| **Flask** | Python Web Framework | Framework web minimaliste pour Python |
| **SQLAlchemy** | Python ORM | ORM puissant pour Python (supporte multiples BDD) |
| **Marshmallow** | Data Validation Library | Validation et sérialisation de données |
| **Bleach** | HTML Sanitization Library | Nettoyage sûr d'HTML (allowlist de balises) |
| **Jinja2** | Python Template Engine | Moteur de templates avec autoescape XSS |
| **Werkzeug** | WSGI Toolkit for Python | Toolkit bas-niveau pour applications WSGI |
| **Pydantic** | Data Validation Library | Validation de données basée sur les type hints Python |
| **Requests** | Python HTTP Library | Bibliothèque pour faire des requêtes HTTP |
| **BeautifulSoup** | HTML/XML Parsing Library | Parser HTML/XML robuste |
| **pytest** | Python Testing Framework | Framework de tests unitaires |
| **Bandit** | Python Security Linter | Outil SAST pour détecter vulnérabilités Python |
| **Safety** | Dependency Vulnerability Checker | Vérification des CVE dans les dépendances Python |
| **Hashlib** | Python Hashing Library | Bibliothèque Python pour hachage et cryptographie |

---

## 🔧 Extensions Flask

| Acronyme | Sens | Description |
|----------|------|-------------|
| **Flask-SQLAlchemy** | SQLAlchemy Extension | Intégration SQLAlchemy avec Flask |
| **Flask-WTF** | WTForms Extension | Protection CSRF et validation de formulaires |
| **Flask-CORS** | CORS Extension | Gestion simplifiée des en-têtes CORS |
| **Flask-Talisman** | Security Headers Extension | Application automatique de headers de sécurité (CSP, HSTS) |
| **Flask-Limiter** | Rate Limiting Extension | Limitation du taux de requêtes (anti-brute force) |
| **Flask-Login** | Authentication Extension | Gestion des sessions utilisateur et authentification |

---

## 🐳 Infrastructure et déploiement

| Acronyme | Sens | Description |
|----------|------|-------------|
| **Docker** | Containerization Platform | Conteneurisation d'applications |
| **CI/CD** | Continuous Integration / Deployment | Intégration et déploiement continus automatisés |
| **WAF** | Web Application Firewall | Pare-feu applicatif pour applications web |
| **EDR** | Endpoint Detection & Response | Détection et réponse aux menaces sur endpoints |
| **DLP** | Data Loss Prevention | Prévention de fuite de données |
| **PRA** | Plan de Reprise d'Activité | Disaster Recovery Plan (DR) |
| **PCA** | Plan de Continuité d'Activité | Business Continuity Plan (BC) |
| **RPO** | Recovery Point Objective | Objectif de point de récupération (données perdables) |
| **RTO** | Recovery Time Objective | Objectif de temps de récupération (downtime toléré) |
| **SQLite** | Lightweight Database | Base de données légère, orientée pédagogique |

---

## 📋 Conformité et données personnelles

| Acronyme | Sens | Description |
|----------|------|-------------|
| **RGPD** | Règlement Général sur la Protection des Données | Loi UE sur la protection des données personnelles |
| **GDPR** | General Data Protection Regulation | Équivalent anglais du RGPD |
| **CNIL** | Commission Nationale de l'Informatique et des Libertés | Autorité française de contrôle RGPD |
| **PCI-DSS** | Payment Card Industry Data Security Standard | Standard de sécurité pour traitement cartes bancaires |

---

## 🔨 Outils de test et pentesting

| Acronyme | Sens | Description |
|----------|------|-------------|
| **Burp Suite** | Penetration Testing Platform | Suite complète de pentesting web (proxy, scanner) |
| **OWASP ZAP** | Web Security Scanner | Scanner open-source de vulnérabilités web |
| **Postman** | API Testing Tool | Outil pour tester et documenter les APIs |
| **Insomnia** | API Testing Client | Client REST pour tester les APIs |
| **SQLMap** | SQL Injection Testing Tool | Outil automatisé de test d'injection SQL |
| **Juice Shop** | Vulnerable Web Application | Application web intentionnellement vulnérable (OWASP) |

---

## 📊 Formats et outils de documentation

| Acronyme | Sens | Description |
|----------|------|-------------|
| **PDF** | Portable Document Format | Format de document portable |
| **ZIP** | File Compression Format | Format d'archive compressée |
| **JSON** | JavaScript Object Notation | Format structuré léger |
| **Markdown** | Lightweight Markup Language | Format texte pour documentation |
| **Marp** | Markdown Presentation Framework | Framework pour créer des présentations en Markdown |
| **PPTX** | PowerPoint Format | Format Microsoft PowerPoint |
| **HTML** | HyperText Markup Language | Format de page web |
| **QCM** | Questionnaire à Choix Multiples | Multiple Choice Questions |

---

## 📚 Références standards

| Acronyme | Sens | Description |
|----------|------|-------------|
| **A01:2021** | Broken Access Control | Catégorie OWASP Top 10 — Contrôle d'accès cassé |
| **A02:2021** | Cryptographic Failures | Catégorie OWASP Top 10 — Défauts cryptographiques |
| **A03:2021** | Injection | Catégorie OWASP Top 10 — Injections (SQL, OS, etc.) |
| **A04:2021** | Insecure Design | Catégorie OWASP Top 10 — Conception non sécurisée |
| **A05:2021** | Security Misconfiguration | Catégorie OWASP Top 10 — Mauvaise configuration |
| **A06:2021** | Vulnerable Components | Catégorie OWASP Top 10 — Composants vulnérables |
| **A07:2021** | Authentication Failures | Catégorie OWASP Top 10 — Défauts d'authentification |
| **A08:2021** | Data Integrity Failures | Catégorie OWASP Top 10 — Défauts d'intégrité |
| **A09:2021** | Logging Failures | Catégorie OWASP Top 10 — Défauts de logging |
| **A10:2021** | Server-Side Request Forgery | Catégorie OWASP Top 10 — SSRF |

---

**Dernière mise à jour :** 2026-05-19  
**Cours :** Security By Design (Master)
