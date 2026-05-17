```markdown
# Référentiel théorique – Security by Design (S1 & S2)

Ce document complète les apports théoriques des deux séances. Il est structuré par grands thèmes et pensé comme **base de connaissances** pour mettre à jour `seance1.md` et `seance2.md`.

---

## 1. Triade CIA et sécurité de l’information

### 1.1 Rappel de la triade CIA

La triade CIA est le modèle de base de la sécurité de l’information (ISO 27001, OWASP, NIST) :

- **Confidentialité**  
  Les informations ne sont accessibles qu’aux entités autorisées.
- **Intégrité**  
  Les informations sont exactes, complètes et non altérées de manière non autorisée.
- **Disponibilité**  
  Les informations et services sont accessibles en temps voulu aux utilisateurs légitimes.

Ces trois objectifs sont **interdépendants** : une application ultra-confidentielle mais souvent indisponible n’est pas « sécurisée » au sens global.

### 1.2 Confidentialité (Confidentiality)

**Objectif** : empêcher la divulgation non autorisée de l’information.

**Menaces typiques** :
- Fuite de base de données (dump SQL, S3 mal configuré, GitHub public…)
- Interception de trafic (sniffing, MITM)
- Escalade de privilèges / accès non autorisés
- Mauvaise isolation multi-tenant (locataire A lisant les données de B)

**Mesures techniques fréquentes** (références aux pratiques mentionnées dans les sources SailPoint, Bitsight, CheckPoint, OWASP) :
- **Contrôles d’accès**  
  - RBAC / ABAC (role-based / attribute-based access control)  
  - Politiques de moindre privilège (Least Privilege)
  - Séparation des responsabilités (SoD – Segregation of Duties)
- **Authentification forte**  
  - MFA (TOTP, WebAuthn/FIDO2, SMS en dernier recours)
  - Gestion de sessions sécurisées (cookies `HttpOnly`, `Secure`, `SameSite`)
- **Chiffrement**  
  - Données **en transit** : TLS (HTTPS), versions et suites cryptographiques à jour
  - Données **au repos** : chiffrement disque ou au niveau base de données (TDE, colonnes chiffrées)
  - Gestion des clés : rotation, HSM/KMS, stockage hors code (pas de clés dans Git)
- **Protection des endpoints**  
  - EDR, antivirus, filtrage web, proxies
  - DLP (Data Loss Prevention) pour surveiller les exfiltrations

**Exemples concrets** :
- Confidentialité d’un mot de passe : stockage hashé + salé, jamais en clair.
- Confidentialité des données d’un client : base chiffrée, accès limité aux seuls microservices nécessaires.

---

### 1.3 Intégrité (Integrity)

**Objectif** : garantir que les données ne sont pas modifiées de manière incorrecte, non autorisée ou accidentelle.

**Menaces typiques** :
- Modification non autorisée des données (attaquant, insider malveillant)
- Erreurs de manipulation (suppression ou modification par erreur)
- Attaques réseau qui altèrent des messages (man-in-the-middle)
- Bugs applicatifs qui corrompent des données

**Mécanismes** :
- **Contrôles d’intégrité cryptographique**  
  - Fonctions de hash (SHA-256, SHA-3…)  
  - HMAC (Hash-based Message Authentication Code) pour coupler intégrité et authentification de la source  
  - Sommes de contrôle (checksums) pour fichiers et backups
- **Signatures numériques**  
  - Authentifier l’auteur d’un message (signature) et garantir l’intégrité du contenu
  - Utilisées dans TLS, JWT signés, mises à jour de logiciels, etc.
- **Contrôles d’intégrité applicatifs et BDD**  
  - Contraintes BDD (PK, FK, NOT NULL, UNIQUE, CHECK)  
  - Transactions ACID, rollbacks
  - Contrôle de version (Git) pour le code et parfois pour les données (event sourcing)
- **Journalisation et audit trail**  
  - Trace de qui a modifié quoi, quand (logs immuables, WORM)
  - Détection des modifications anormales (SIEM, corrélation d’événements)

**Exemples** :
- Intégrité d’une transaction bancaire : double écriture, journaux d’audit, contrôles métier (débit = crédit), signatures.
- Intégrité des tokens JWT : signature HMAC ou RSA/EC, refus de tout token non vérifiable.

---

### 1.4 Disponibilité (Availability)

**Objectif** : assurer l’accès aux systèmes et données pour les utilisateurs autorisés, dans les délais requis.

**Menaces typiques** (voir les exemples Bitsight / Inetdoc) :
- Attaques DDoS
- Ransomware (données indisponibles car chiffrées)
- Pannes matérielles (disques, serveurs, réseau)
- Catastrophes (incendie, inondation, perte de datacenter)
- Erreurs de configuration ou déploiements ratés

**Mesures** :
- **Architecture résiliente**  
  - Redondance (serveurs, bases, réseau, zones de disponibilité)
  - Load balancing, autoscaling
  - Répartition géographique (multi-régions)
- **Sauvegardes et PRA/PCA**  
  - Backups réguliers + test de restauration
  - Plan de Reprise d’Activité (RPO/RTO définis)
  - Plan de Continuité (bascule sur site secondaire, cloud multi-provider potentiellement)
- **Surveillance & alerting**  
  - Monitoring (APM, métriques, logs)
  - Alertes sur erreurs, dégradations de performance, saturation de ressources
- **Protection DDoS et limites**  
  - Reverse proxy / WAF / services anti-DDoS
  - Rate limiting et quotas (voir plus loin)
  - Mécanismes de dégradation progressive (graceful degradation, feature flags)

**Exemple** :
- Une API critique est répliquée sur plusieurs instances derrière un load balancer, avec WAF + rate limiting + backups de la base + plan de bascule si une région tombe.

---

## 2. RGPD et Privacy by Design

### 2.1 Principes clés du RGPD (Article 5)

Le RGPD impose des **principes** que tout traitement de données personnelles doit respecter. Ils recoupent fortement la triade CIA :

1. **Licéité, loyauté, transparence**  
   - Base légale (consentement, contrat, obligation légale, intérêt légitime, etc.)  
   - Information claire et accessible (politique de confidentialité, mentions).
2. **Limitation des finalités**  
   - Les données ne sont collectées que pour des objectifs déterminés, explicites, légitimes.
   - Pas de réutilisation incompatible avec ces finalités (pas de « tout faire avec tout »).
3. **Minimisation des données**  
   - Ne collecter que ce qui est strictement nécessaire (data minimization).
4. **Exactitude**  
   - Données à jour, exactes. Mécanismes de rectification (droit de rectification).
5. **Limitation de la conservation**  
   - Durées de rétention définies ; purge ou anonymisation au-delà.
6. **Intégrité et confidentialité**  
   - Sécurité technique et organisationnelle appropriée (mesures CIA ci-dessus).

### 2.2 Privacy by Design & by Default (Article 25)

**Privacy by Design** : intégrer la protection des données dès la conception.

Exemples concrets à relier aux exercices Python :

- **Minimisation dans le modèle de données**  
  - Ne pas stocker d’infos inutiles (date de naissance si âge suffit, pas de log des mots de passe, etc.).
  - Champs optionnels par défaut (ex. marketing opt-in).
- **Pseudonymisation / anonymisation**  
  - Remplacer l’email par un identifiant pseudonyme dans certains logs.
  - Anonymiser les datasets utilisés pour le machine learning ou les tests.
- **Sécurité par défaut**  
  - Paramètres les plus protecteurs par défaut (profil privé, cookies `SameSite=Lax`, MFA proposé, etc.).
  - Désactivation par défaut des fonctionnalités risquées (téléversement de fichiers, exécution de HTML).

**Privacy by Default** : les paramètres par défaut d’une app doivent être les plus protecteurs (l’utilisateur ne doit pas avoir à « désactiver » un traçage agressif par exemple).

### 2.3 Obligations en cas de violation de données

Lors d’une **violation de données à caractère personnel** (accès non autorisé, perte, destruction…) :

- **Notification à l’autorité de contrôle** (CNIL en France)  
  - Dans les 72h après en avoir pris connaissance (sauf si risques improbables pour les droits et libertés).
- **Notification aux personnes concernées**  
  - Si la violation est susceptible d’entraîner un risque élevé pour leurs droits et libertés (ex. vol de mots de passe, de données sensibles).
- **Documentation interne**  
  - Registre des violations : date, nature, impact, mesures prises.
- **Sanctions potentielles**  
  - Jusqu’à 20 M€ ou 4% du CA annuel mondial (le plus élevé des deux).

Pour la mise à jour de `seance1.md`, on peut ajouter un tableau liant **type de données** → **risques** → **mesures techniques** (hash, chiffrement, logs limités…).

---

## 3. Vulnérabilités d’injection (SQLi, XSS, SSTI)

### 3.1 Injection SQL (SQLi)

#### 3.1.1 Principe

L’attaque consiste à injecter du SQL dans une requête construite à partir de concaténation de chaînes, permettant :

- Bypass d’authentification (`' OR '1'='1`)
- Exfiltration de données (`UNION SELECT`)
- Modification / suppression de données (`; DROP TABLE users;--`)
- Prise de contrôle du serveur via fonctionnalités DB avancées (xp_cmdshell, COPY, LOAD_FILE, etc.)

#### 3.1.2 Types de SQLi

- **Classique (in-band)**  
  - L’attaquant voit directement le résultat (erreurs SQL, données ajoutées dans la réponse).
- **Error-based**  
  - Exploitation des messages d’erreur détaillés pour récupérer des informations.
- **Union-based**  
  - Utilisation de `UNION SELECT` pour extraire des données d’autres tables.
- **Blind SQLi**  
  - L’application ne renvoie pas directement les résultats. L’attaquant déduit les infos via :
    - **Boolean-based** : si la condition est vraie → comportement différent.
    - **Time-based** : si la condition est vraie → la réponse est retardée (`SLEEP`, `pg_sleep`).

Les challenges SQLi de la séance 1 exploitent ces variantes, notamment la **blind SQLi time-based**.

#### 3.1.3 Contre-mesures

- **Requêtes paramétrées / prepared statements**  
  - Ne jamais concaténer des variables utilisateur dans le SQL.
  - Utiliser les placeholders (`?`, `:name`, `$1`) fournis par les drivers.
- **ORM** (SQLAlchemy, Django ORM, etc.)  
  - Par défaut, utilisent des requêtes paramétrées.
- **Validation stricte des entrées**  
  - Typage fort : ID numériques, enums, etc.
- **Moindre privilège sur le compte DB**  
  - Interdire `DROP`, `ALTER` si non nécessaire.
- **Désactivation des messages d’erreur détaillés en prod**  
  - Log côté serveur, message générique côté client.

---

### 3.2 Cross-Site Scripting (XSS)

#### 3.2.1 Principe

Permet d’injecter et d’exécuter du JavaScript arbitraire dans le navigateur d’un utilisateur, dans le contexte de confiance de la cible.

**Impacts classiques** :
- Vol de cookies de session (si non `HttpOnly`)
- Défiguration de la page, redirections, phishing
- Keylogging, actions à la place de l’utilisateur
- Accès aux APIs web accessibles depuis cette origine

#### 3.2.2 Types de XSS

1. **Reflected XSS**
   - La charge malveillante vient d’un paramètre de requête ou POST, reflétée dans la réponse.
   - Ex: `http://site/search?q=<script>...</script>`

2. **Stored (persistent) XSS**
   - La charge est stockée côté serveur (BDD, commentaire, profil).
   - Chaque visiteur de la page exécute le script.

3. **DOM-based XSS**
   - L’injection et l’exécution sont entièrement côté client, via le JavaScript de la page (ex. `innerHTML` sur `location.hash` non filtré).
   - Ici, la vulnérabilité se trouve dans le code JS, pas dans le backend.

#### 3.2.3 Contre-mesures

- **Échappement contextuel correct**  
  - HTML : échappement des caractères spéciaux (`<`, `>`, `&`, `"`, `'`)  
  - Attributs : plus strict, pas de guillemets non échappés  
  - JavaScript : ne jamais injecter directement des données dans du JS inline (`var data = '...';`)
  - URL : encodeURIComponent / `quote` côté serveur
- **Utiliser des templates sécurisés** (Jinja2, Twig, etc.)  
  - Auto-escape activé par défaut et respecté (ne pas utiliser `|safe` à la légère).
- **Validation et filtrage en entrée**  
  - Limiter les caractères/fonctionnalités autorisées pour certains champs (ex. Markdown, BBCode).
- **CSP (Content Security Policy)**  
  - Interdire `unsafe-inline`, restreindre les sources de scripts.
  - Utilisation de **nonces** ou hashes pour autoriser certains scripts inline.
- **Cookies `HttpOnly`**  
  - Empêche `document.cookie` de lire les cookies, limitant l’impact de certaines XSS.

---

### 3.3 Server-Side Template Injection (SSTI)

#### 3.3.1 Principe

Au lieu d’injecter du JS dans le navigateur, l’attaquant injecte des **expressions de template** dans un moteur côté serveur (Jinja2, Twig, Freemarker…), permettant :

- De lire des variables sensibles (`{{ config }}`, `{{ request }}`)
- D’atteindre l’environnement Python/OS (`{{ self.__dict__ }}`, etc.)
- Potentiellement d’obtenir une exécution de code à distance (RCE)

Exemple vulnérable (déjà mentionné dans `seance2.md`) :

```python
name = request.args.get('name', 'World')
template = f"<h1>Hello {name}</h1>"  # Concaténation dangereuse
return render_template_string(template)
```

**Payload de test** : `?name={{7*7}}` → si 49 s’affiche, c’est vulnérable.

#### 3.3.2 Contre-mesures

- **Ne jamais construire de templates par concaténation** avec des données utilisateur.
- Utiliser **des variables de contexte** :

```python
return render_template("hello.html", name=name)
```

- **Désactiver les fonctionnalités dynamiques superflues** côté moteur (selon le framework).
- Valider strictement les entrées utilisées dans les templates (ex. n’autoriser que du texte simple, pas de syntaxe de template).

---

## 4. Protocole HTTP, SOP, CORS, CSRF et protections navigateur

### 4.1 Same-Origin Policy (SOP)

**Définition** : politique de sécurité fondamentale des navigateurs. Deux documents partagent la même origine s’ils ont le **même schéma (protocole), domaine, port**.

**Conséquence** : du JavaScript exécuté sur `https://app.com` n’a pas le droit de lire librement la réponse d’une requête vers `https://api.app.com` (domaine différent), sauf si CORS l’autorise explicitement.

- SOP protège surtout l’accès au **contenu** des réponses (DOM, XHR, fetch), pas l’envoi de requêtes (les requêtes cross-origin sont possibles, mais la lecture de la réponse est limitée).

---

### 4.2 CORS (Cross-Origin Resource Sharing)

**Objectif** : permettre à un serveur d’exposer certaines ressources à des origines différentes, de manière contrôlée.

**Mécanisme** :
- Le navigateur envoie l’en-tête `Origin: https://app.com` dans la requête.
- Le serveur répond, s’il accepte, avec :
  - `Access-Control-Allow-Origin: https://app.com` (ou `*` dans certains cas)
  - éventuellement `Access-Control-Allow-Credentials: true` si cookies/credentials autorisés
- Pour certains types de requêtes (méthodes non simples, headers custom), le navigateur fait un **preflight** `OPTIONS`.

**Bonnes pratiques** :
- Ne jamais répondre avec `Access-Control-Allow-Origin: *` sur des endpoints authentifiés avec cookies.
- Restreindre précisément les origines autorisées (whitelist).
- Vérifier côté serveur l’**autorisation applicative** indépendamment de CORS (CORS ne remplace pas l’authz).

---

### 4.3 CSRF (Cross-Site Request Forgery)

#### 4.3.1 Principe

CSRF exploite la manière dont les navigateurs gèrent les **cookies** : pour un domaine donné, le navigateur envoie automatiquement les cookies associés, quelle que soit la page d’origine de la requête.

Scénario typique (déjà illustré dans `seance2.md`) :
- Utilisateur connecté à `bank.com`.
- Il visite un site malveillant qui contient un formulaire ou un script effectuant un `POST` vers `https://bank.com/transfer`.
- Le navigateur ajoute automatiquement les cookies de session → la requête est authentifiée.

#### 4.3.2 Contre-mesures principales

1. **Token CSRF (Synchronizer Token Pattern)**  
   - Le serveur génère un token aléatoire, stocké côté serveur (session) et inséré dans le formulaire HTML.  
   - À la soumission, le serveur vérifie que le token reçu correspond à celui stocké.
   - L’attaquant ne peut pas deviner ni lire ce token (même origine + pas de XSS).

2. **SameSite cookies**  
   - `SameSite=Lax` ou `Strict` empêche (ou limite) l’envoi de cookies pour les requêtes cross-site.
   - Très efficace contre beaucoup de scénarios CSRF, mais pas suffisant si :
     - le site permet des requêtes sensibles en GET (le Lax permet certains GET de navigation),  
     - certaines combinaisons de navigateurs / anciennes versions.

3. **Vérification d’Origin / Referer**  
   - Vérifier que l’en-tête `Origin` ou `Referer` correspond au domaine attendu.
   - Utile en *défense en profondeur*, pas toujours fiable (certains proxy suppriment ces headers).

4. **Séparation des domaines**  
   - Séparer les interfaces sensibles dans un domaine dédié (ex. `secure.bank.com`) et éviter les inclusions cross-site.

Pour la mise à jour de `seance2.md`, détailler les **modes SameSite** (`Lax`, `Strict`, `None`) et leurs effets sur CSRF.

---

## 5. Authentification et gestion des mots de passe

### 5.1 Stockage des mots de passe

Les bonnes pratiques recommandées par **OWASP Password Storage Cheat Sheet** :

- **Jamais de stockage en clair**.
- **Hashage avec une fonction de dérivation de clé lente** (bcrypt, scrypt, Argon2, PBKDF2).  
  - Lenteur = rend le bruteforce coûteux (CPU/GPU).
- **Sel unique par mot de passe** (généré aléatoirement) :
  - Empêche l’utilisation de rainbow tables.
  - Stocké en clair avec le hash (format spécifique à chaque algorithme).
- **Paramètres ajustés** (CPU, mémoire, itérations) selon la puissance des serveurs, réévalués dans le temps (d’où la notion de `needs_rehash`).

### 5.2 Politique de mots de passe

Points clés (cf. NIST SP 800-63B & OWASP) :

- Longueur minimale : 8–12 caractères minimum.  
- Encourager la **passphrase** plutôt que des règles trop complexes (favorise les mots de passe mémorisables).
- Bloquer :
  - Les mots de passe trop courants (dictionnaires de mots de passe compromis – `HaveIBeenPwned`).
  - Les suites triviales (123456, qwerty, password…).
- Ne pas imposer de rotation fréquente arbitraire (sauf en cas de suspicion de compromission).

### 5.3 Défense contre brute force & attaques par dictionnaire

- **Rate limiting** (voir section 6 ci-dessous).
- **Lock-out / backoff progressif** :
  - Ex. après N échecs, bloquer temporairement le compte ou exiger un CAPTCHA / MFA.
- **Temps de réponse constant** (ou quasi) :
  - Même pour les utilisateurs inexistants, effectuer une opération de hash fictive pour masquer la différence de temps (protection contre les attaques par **timing**).

### 5.4 MFA (Multifactor Authentication)

- Facteurs :  
  - Ce que je sais (mot de passe)  
  - Ce que je possède (smartphone, token)  
  - Ce que je suis (biométrie)
- Recommandé sur les comptes administrateurs et opérations sensibles (paiements, changements d’email).

---

## 6. Contrôles d’accès, autorisation et IDOR

### 6.1 Contrôles d’accès (Authorization)

**Différence AuthN / AuthZ** :
- **Authentification (AuthN)** : qui êtes-vous ? (login/mot de passe, MFA…)
- **Autorisation (AuthZ)** : que pouvez-vous faire ? (vision/ rôle / attributs)

**Types de modèles** :
- **RBAC** (Role-based) : rôles (admin, user, manager…).
- **ABAC** (Attribute-based) : décisions basées sur des attributs (service, pays, statut de compte, etc.).
- **ACL** (Access Control List) : listes explicites de droits par ressource.

### 6.2 IDOR (Insecure Direct Object Reference)

**Principe** : l’application référence directement des objets sensibles par un identifiant prévisible (ex. `/order/123`) sans vérifier que l’utilisateur a le droit de voir/éditer cette ressource.

**Exemple** :
- Un utilisateur modifie l’URL `/orders/42` en `/orders/41` et peut voir la commande d’un autre utilisateur.

**Contre-mesures** :
- Toujours **vérifier l’appartenance** de la ressource à l’utilisateur actuellement authentifié.
- Utiliser des identifiants non prédictibles (UUID, tokens), mais cela n’est qu’un durcissement, pas une vraie protection.
- Tests automatisés pour les accès croisés (comme prévu dans `test_idor_protection_on_orders`).

---

## 7. Validation des entrées et DoS applicatif

### 7.1 Validation des entrées

**Objectifs** :
- Prévenir les injections (SQLi, XSS, XXE, SSTI).
- Prévenir les erreurs ou plantages (types incorrects, formats invalides).
- Prévenir certaines attaques de DoS (regex catastrophiques, payloads trop gros).

**Recommandations** :
- Valider **au plus près de la frontière** (API, formulaires).
- Utiliser des **schemas** (Pydantic, Marshmallow, Cerberus…) avec types forts.
- Limiter la taille des données (longueur des strings, taille des fichiers uploadés).

### 7.2 Regex et ReDoS

Certaines regex mal construites peuvent provoquer des temps de traitement exponentiels (ReDoS).

Mesures :
- Éviter les regex trop complexes ou avec backtracking potentiellement massif.
- Limiter la taille de l’input.
- Utiliser des bibliothèques ou fonctions avec timeout (comme le `safe_regex_match` dans `seance2.md`).

---

## 8. Limitation de débit (Rate Limiting) et protections automatisées

### 8.1 Rate Limiting

**Objectif** : limiter le nombre de requêtes par unité de temps pour :

- Atténuer brute force, enumeration d’IDs, scraping.
- Protéger la disponibilité (composante « A » de CIA).

**Concepts** :
- Clés de comptage (IP, user_id, combination, endpoint).
- Stratégies : Token Bucket, Leaky Bucket, Fixed Window, Sliding Window.

Bonnes pratiques :
- Différencier les limites par type d’endpoint (login vs. assets).
- Retourner `HTTP 429 Too Many Requests` avec un en-tête `Retry-After`.

---

### 8.2 CAPTCHA / Bot Detection

- reCAPTCHA v2/v3, hCaptcha, solutions maison.
- Utilisation adaptée : sur login après plusieurs échecs, sur endpoints sensibles, pas sur toutes les requêtes (UX).
- Ne pas dépendre uniquement du CAPTCHA (peut être contourné, nécessite défense en profondeur).

---

## 9. SDLC sécurisé (Secure Development Life Cycle)

### 9.1 Principes

Un **SDLC sécurisé** intègre la sécurité à toutes les phases :

1. **Conception**  
   - Analyse de risque, modèle de menace (Threat Modeling – STRIDE, etc.), revue d’architecture.
2. **Développement**  
   - Bonnes pratiques (OWASP ASVS, Cheat Sheets).
   - Revue de code incluant des points de sécurité.
   - Linters et hooks pre-commit.
3. **Tests**  
   - **SAST** : analyse statique du code (Bandit, Semgrep).  
   - **DAST** : scanner dynamique (OWASP ZAP, Burp).  
   - Tests unitaires / intégration spécifiques sécurité.
4. **Déploiement / exploitation**  
   - Hardening (OS, conteneurs, reverse proxies).
   - Gestion des secrets (Vault, KMS).
   - Monitoring, logs centralisés, SIEM.
   - Plan de réponse à incident (IR).

### 9.2 Outils Python typiques

- **SAST**  
  - Bandit (Python)  
  - Semgrep (multi-langage)
- **SCA**  
  - Safety  
  - pip-audit
- **Tests et intégration**  
  - pytest, coverage
  - CI/CD (GitHub Actions, GitLab CI, etc.) avec étapes SAST/SCA

---

## 10. CSP (Content Security Policy) – Complément XSS

**Objectif** : fournir une « politique » au navigateur pour limiter ce qu’une page peut charger/exécuter.

Exemples de directives utiles :

- `default-src 'self';`  
  - Par défaut, ne charger que depuis la même origine.
- `script-src 'self' 'nonce-<valeur>';`  
  - Scripts autorisés seulement depuis la même origine et avec un nonce spécifique.  
  - Interdit les scripts inline sans nonce.
- `object-src 'none';`  
  - Désactive Flash, applets, etc.
- `frame-ancestors 'none';`  
  - Empêche l’intégration dans des iframes (clickjacking).
- `report-uri` / `report-to`  
  - Permet d’envoyer des rapports de violation CSP.

**Stratégies** :
- Commencer par `Content-Security-Policy-Report-Only` pour observer les violations sans bloquer.
- Introduire progressivement des règles plus strictes.
- Utiliser des nonces générées par requête pour les scripts indispensables.

---

Ce référentiel peut être utilisé pour :

- Ajouter des **encarts théoriques** plus complets dans `seance1.md` (CIA, RGPD, attaques d’injection, XSS, SOP/CORS).
- Enrichir `seance2.md` sur **CSRF**, **SSTI**, **authentification sécurisée**, **rate limiting**, **CAPTCHA** et **SDLC**.
- Construire des questions de quiz (QCM) plus variées et argumentées.
```