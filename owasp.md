```markdown
# Référentiel OWASP – Top 10 Web & Top 10 API

Ce document synthétise les contenus principaux de l’**OWASP Top 10 (applications web)** et de l’**OWASP API Security Top 10**, en français, avec des explications pédagogiques et orientées « développement sécurisé ».

---

## 1. OWASP Top 10 – Applications Web

> Source principale : [OWASP Top 10 2021](https://owasp.org/Top10/2021/)  
> (en 2026, c’est encore la version de référence officielle, en attendant la stabilisation complète de 2025).

### A01:2021 – Broken Access Control (Contrôles d’accès défaillants)

**Idée clé**  
Les règles « qui a le droit de faire quoi » sont mal implémentées ou absentes, permettant à un attaquant d’accéder à des données ou à des actions qui ne devraient pas être accessibles.

**Exemples courants**
- IDOR / BOLA : `/users/123` accessible par n’importe quel utilisateur.
- Endpoints « admin » non protégés ou cachés seulement par l’UI.
- Contrôles d’accès réalisés uniquement côté client (JS) et non vérifiés côté serveur.

**Mesures**
- Implémenter une politique d’autorisation claire (RBAC/ABAC).
- Vérifier systématiquement, côté serveur, l’appartenance/les droits sur chaque ressource.
- Tests automatisés d’accès horizontal (utilisateur A accédant aux données de B).

---

### A02:2021 – Cryptographic Failures (Défaillances cryptographiques)

**Idée clé**  
L’objectif n’est pas la crypto « exotique », mais tout ce qui touche à la **confidentialité** et à la **protection de données sensibles**.

**Exemples**
- Absence de HTTPS/TLS ou versions obsolètes.
- Mots de passe stockés en clair ou avec des hash rapides (MD5, SHA-1).
- Clés de chiffrement dans le code source ou dans un dépôt Git public.
- Algorithmes ou modes de chiffrement obsolètes (RC4, ECB, etc.).

**Mesures**
- TLS partout, configuration à jour (protocoles, suites, HSTS).
- Hashage des mots de passe avec bcrypt, Argon2, PBKDF2, etc.
- Gestion centralisée des secrets (Vault, KMS, variables d’environnement).
- Inventaire des données sensibles et choix de mesures adaptées (chiffrement, masquage).

---

### A03:2021 – Injection

**Idée clé**  
L’application intègre des données non fiables directement dans des requêtes ou des interpréteurs (SQL, NoSQL, LDAP, OS, etc.), permettant à l’attaquant de modifier la commande exécutée.

**Exemples**
- SQL injection : `SELECT * FROM users WHERE name = ' " + userInput + " ';`
- Command injection : `os.system("ping " + user_input)`
- NoSQL injection, LDAP injection, template injection (SSTI).

**Mesures**
- Requêtes paramétrées / prepared statements.
- API de haut niveau (ORM, builders) au lieu de concaténation de chaînes.
- Validation stricte des entrées (types, listes blanches).
- Principe de moindre privilège sur les comptes DB / OS.

---

### A04:2021 – Insecure Design (Conception non sécurisée)

**Idée clé**  
Les failles ne viennent pas seulement de bugs, mais souvent d’une **architecture** ou d’un **modèle métier** mal conçus (absence de sécurité dès la conception).

**Exemples**
- Pas de séparation claire des rôles / zones de confiance.
- Flux métier permettant des contournements (ex: réinitialisation de mot de passe peu robuste).
- Prévoir de stocker plus de données qu’utile (violation de « privacy by design »).

**Mesures**
- Pratique systématique du **Threat Modeling** (STRIDE, etc.).
- Patterns de conception sécurisés (OWASP ASVS, Cheat Sheets).
- Intégrer la sécurité dès les premières étapes du cycle de vie (SDLC sécurisé).

---

### A05:2021 – Security Misconfiguration (Mauvaise configuration de sécurité)

**Idée clé**  
Les composants sont mal configurés ou laissés avec des réglages par défaut : cela ouvre des portes inutiles.

**Exemples**
- Panneaux d’admin publics, comptes par défaut non changés.
- Messages d’erreur détaillés exposés en production.
- Services inutiles exposés, ports ouverts, CORS trop permissif.

**Mesures**
- Processus d’hardening systématique (OS, serveur web, DB, reverse proxy).
- « Secure by default » : désactiver ce qui n’est pas nécessaire.
- Gestion de la config par code (Infrastructure as Code, templates reproductibles).
- Revue de configuration régulière, scans de configuration.

---

### A06:2021 – Vulnerable and Outdated Components (Composants vulnérables ou obsolètes)

**Idée clé**  
Bibliothèques, frameworks, serveurs, runtime non patchés ou obsolètes sont une porte d’entrée privilégiée.

**Exemples**
- Utilisation d’une version vulnérable de Spring, Struts, Log4j, etc.
- Paquets Python/Node obsolètes avec CVE connus.
- Composants front-end non maintenus.

**Mesures**
- Inventaire des dépendances (SBoM) et gestion SCA (Software Composition Analysis).
- Mise à jour régulière via un processus (patch management).
- Définir une politique de support des versions (LTS, breakpoints de mise à niveau).

---

### A07:2021 – Identification and Authentication Failures (Défaillances d’identification et d’authentification)

**Idée clé**  
Les mécanismes de login, session, MFA, récupération de compte sont faibles ou mal implémentés.

**Exemples**
- Sessions prévisibles, cookies non protégés (`HttpOnly`, `Secure`).
- Absence de protections contre brute force (rate limiting, lockout).
- Tokens JWT non signés ou signés avec des secrets faibles.

**Mesures**
- Stockage sécurisé des mots de passe, MFA pour comptes sensibles.
- Gestion robuste des sessions (invalidation, rotation, cookies sécurisés).
- Politique de mots de passe raisonnable + vérification contre listes compromises.
- Tests spécifiques sur l’authentification (OWASP ASVS – section AuthN).

---

### A08:2021 – Software and Data Integrity Failures (Défaillances d’intégrité logicielle et des données)

**Idée clé**  
Absence de mécanismes garantissant que le logiciel et les données n’ont pas été modifiés de manière non autorisée (supply chain, mises à jour, CI/CD).

**Exemples**
- Mise à jour d’application téléchargée sans vérification de signature.
- Pipeline CI/CD sans contrôle d’intégrité et sans restrictions de droits.
- Application qui consomme des plugins ou scripts tiers sans validation.

**Mesures**
- Signatures numériques (logiciels, containers) et vérification côté déploiement.
- Hardening et séparation des rôles dans la chaîne CI/CD.
- Contrôles d’intégrité (hash, HMAC) pour les données sensibles.

---

### A09:2021 – Security Logging and Monitoring Failures (Défaillances de journalisation et de monitoring)

**Idée clé**  
Sans logs pertinents ni surveillance, on ne voit pas les attaques, ou trop tard.

**Exemples**
- Absence de logs sur les actions critiques (login, changements de droits).
- Logs trop pauvres ou stockés localement sans centralisation.
- Aucune alerte sur les événements anormaux (nombre de tentatives, etc.).

**Mesures**
- Définir une politique de logging (quoi loguer, à quel niveau, où).
- Centralisation (ELK, SIEM…), corrélation d’événements, alertes.
- Protection des logs (confidentialité, intégrité, rétention conforme RGPD).

---

### A10:2021 – Server-Side Request Forgery (SSRF)

**Idée clé**  
L’application effectue des requêtes HTTP côté serveur vers une URL fournie par l’utilisateur, sans restriction. L’attaquant s’en sert pour atteindre des ressources internes ou protégées.

**Exemples**
- Service qui « prévisualise » une URL et permet d’appeler `http://localhost:8080/admin`.
- Exploitation de metadata cloud (`http://169.254.169.254/`) via SSRF.
- Proxy interne utilisé comme rebond vers le réseau interne.

**Mesures**
- Listes blanches strictes d’URL / domaines autorisés.
- Interdire les IP internes, localhost, adresses privées, etc.
- Resolver et client HTTP sécurisés (résolution DNS contrôlée, pas de redirections vers internes).
- Segmentation réseau pour limiter ce que le serveur peut atteindre.

---

## 2. OWASP API Security Top 10 – APIs Web

> Source principale : [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)  
> Version de référence : **API Security Top 10 2019**, toujours largement utilisée dans la documentation et les formations.

Les API exposent des fonctionnalités et des données de manière structurée, mais très directe. Beaucoup de protections implicites des applications web traditionnelles (session, templating, UI) disparaissent, ce qui explique une liste spécifique.

### API1:2019 – Broken Object Level Authorization (BOLA / IDOR sur API)

**Idée clé**  
La vulnérabilité la plus fréquente en API : l’API permet à un utilisateur d’accéder ou de modifier des ressources qui ne lui appartiennent pas, via des identifiants manipulables.

**Exemples**
- `GET /api/orders/1234` accessible par n’importe quel client authentifié.
- `PATCH /api/users/42` qui ne vérifie pas que l’utilisateur connecté est bien l’utilisateur 42 ou un admin.

**Mesures**
- Vérifier systématiquement, pour chaque requête, que l’objet appartient à l’appelant ou est autorisé par son rôle.
- Tests automatisés BOLA (essayer d’accéder aux ressources d’autres utilisateurs).
- Ne pas se reposer sur des IDs opaques seuls : toujours vérifier l’autorisation.

---

### API2:2019 – Broken User Authentication

**Idée clé**  
Problèmes d’authentification adaptés au contexte API (tokens, OAuth, sessions stateless).

**Exemples**
- JWT sans expiration ou sans signature robuste.
- Réutilisation de tokens expirés ou non invalidés à la révocation.
- Endpoints d’authentification sans protection contre brute force.

**Mesures**
- JWT signés avec des clés fortes, expirations courtes, rotation de tokens.
- Revocation list, refresh tokens bien gérés.
- Rate limiting et mesures anti-brute force sur les endpoints de login.
- MFA pour les opérations sensibles, même en contexte API (par exemple Out-of-band).

---

### API3:2019 – Excessive Data Exposure

**Idée clé**  
L’API renvoie trop de données, en comptant sur le front-end pour masquer ce qui ne doit pas être affiché.

**Exemples**
- Réponse JSON incluant des champs sensibles (`roles`, `ssn`, `password_hash`) mais non utilisés par l’UI.
- Retour d’objets complets là où seules quelques propriétés sont nécessaires.

**Mesures**
- Filtrer côté serveur : ne jamais renvoyer plus que nécessaire.
- DTO (Data Transfer Objects) ou serializers explicitant les champs exposés.
- Revue systématique des réponses pour détecter les sur-expositions.

---

### API4:2019 – Lack of Resources & Rate Limiting

**Idée clé**  
L’API ne contrôle pas le volume de requêtes ni la taille des ressources, permettant le DoS, l’extraction massive, le brute force.

**Exemples**
- Aucun rate limit sur `POST /login`.
- Endpoints de recherche sans pagination, pouvant renvoyer des milliers d’objets.
- Upload de fichiers sans limite de taille ou contrôle de format.

**Mesures**
- Rate limiting (par IP, token, utilisateur), quotas.
- Pagination obligatoire pour les listes.
- Limites de taille pour les payloads et les fichiers uploadés.
- Timeouts serveur raisonnables, cancellation côté client.

---

### API5:2019 – Broken Function Level Authorization

**Idée clé**  
Les contrôles d’accès sur les **fonctions** (endpoints, actions) sont mal gérés. Un utilisateur non admin peut accéder à des actions d’admin, par exemple.

**Exemples**
- `/api/admin/users` accessible sans vérification de rôle.
- Distinction insuffisante entre endpoints de lecture et d’administration.

**Mesures**
- Modèle d’autorisations clair (RBAC/ABAC) appliqué au niveau des routes.
- Vérification des rôles/permissions sur chaque endpoint.
- Revue complète des routes (documentation vs implémentation réelle).

---

### API6:2019 – Mass Assignment

**Idée clé**  
L’API mappe directement les données reçues (JSON) sur un modèle interne, sans restreindre les champs modifiables. L’attaquant peut modifier des champs qu’il ne devrait pas.

**Exemples**
- `PATCH /api/users/me` accepte un JSON avec `{"role": "admin"}` qui est pris en compte.
- Champs comme `is_active`, `balance`, `is_admin` modifiables via l’API par un client ordinaire.

**Mesures**
- Listes blanches de champs acceptés pour chaque endpoint (binding explicite).
- DTO/serializers distincts pour lecture et écriture.
- Tests ciblés de mise à jour de champs internes/sensibles via l’API.

---

### API7:2019 – Security Misconfiguration (API)

**Idée clé**  
Les API héritent des mêmes problèmes de configuration que les applis web, mais avec quelques spécificités (CORS, headers, debug, docs).

**Exemples**
- CORS permissif (`Access-Control-Allow-Origin: *` avec `Allow-Credentials: true`).
- Interface Swagger ouverte avec toutes les opérations de prod, sans auth.
- Messages d’erreur internes détaillés renvoyés au client.

**Mesures**
- CORS strict (origines autorisées, méthodes, credentials).
- Protection des interfaces de documentation (auth, réduction d’info en prod).
- Désactiver debug/logs verbeux en environnement de production.

---

### API8:2019 – Injection (API)

**Idée clé**  
Les mêmes problématiques d’injection (SQL, NoSQL, OS, LDAP, etc.), mais pour des endpoints typiquement « data-centric ».

**Exemples**
- Filtrage ou tri basé sur des paramètres directement insérés dans une requête DB ou un pipeline de recherche.
- Injection dans des scripts ou des commandes lancés par l’API.

**Mesures**
- Paramétrage systématique des requêtes (ORM, APIs DB).
- Validation stricte des paramètres (types, listes de valeurs autorisées).
- Pas de construction dynamique de commande à partir de données client.

---

### API9:2019 – Improper Assets Management

**Idée clé**  
Mauvaise gestion du **cycle de vie des versions** et de l’inventaire des API. Des endpoints oubliés, non documentés ou dépréciés restent accessibles.

**Exemples**
- Ancienne version `/v1` toujours exposée et non maintenue, avec failles connues.
- Endpoints internes ou de test laissés déployés en prod.

**Mesures**
- Catalogue complet des APIs (documentation, versions, propriétaires).
- Stratégie de versionning (dépréciation, retrait planifié).
- Tests réguliers et scans pour découvrir les endpoints non documentés (shadow APIs).

---

### API10:2019 – Insufficient Logging & Monitoring (API)

**Idée clé**  
Comme pour A09 du Top 10 web, mais focalisé sur les API : appels massifs, patterns d’abus, anomalies de tokens.

**Exemples**
- Absence de logs pour les appels sensibles (écriture, suppression).
- Aucune alerte sur un volume anormal de requêtes, même sur des endpoints critiques.
- Incapacité à tracer qui a fait quoi lors d’un incident.

**Mesures**
- Journalisation contextualisée : identifiant de l’API client, user_id, IP, endpoint, statut.
- Centralisation des logs, dashboards API, alertes sur patterns anormaux.
- Corrélation avec les logs d’authentification, WAF, reverse proxy.

---

## 3. Comment utiliser ce référentiel dans vos futurs prompts

Pour mettre à jour vos fichiers de séance, vous pouvez par exemple :

- Ajouter une **section théorique** dans `seance1.md` :
  - Rappel OWASP Top 10 web 2021, en particulier A01 (Broken Access Control), A02 (Cryptographic Failures) et A03 (Injection), avec lien vers les exercices.
- Ajouter une **section « API & microservices »** dans `seance2.md` :
  - Rappel OWASP API Security Top 10, insistant sur API1 (BOLA), API3 (Excessive Data Exposure) et API4 (Rate Limiting), avec exemples de code Python/Flask/FastAPI.
- Construire des **questions de quiz** :
  - « À quel risque OWASP correspond ce scénario ? »
  - « Quels contrôles mettre en place pour réduire API6: Mass Assignment dans cette API ? »

Ce markdown peut servir de base à un futur prompt du type :  
> « Mets à jour `seance1.md` et `seance2.md` en intégrant les explications du référentiel OWASP (sections X, Y, Z) et en ajoutant des exemples de code et des questions de quiz. »

```