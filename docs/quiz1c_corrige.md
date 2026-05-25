⚠️ **DOCUMENT ENSEIGNANT — NE PAS DISTRIBUER AUX ÉTUDIANTS**

Ce fichier contient le corrigé détaillé et le barème du Quiz 1.C (36 questions, 25 min). À réserver à la plateforme pédagogique institutionnelle.

---

# Quiz 1.C — Corrigé détaillé et Barème

## 📋 Réponses correctes (Vue d'ensemble)

```
SECTION 1 — Triade CIA
Q1 : B    Q2 : C    Q3 : C    Q4 : B    Q5 : A    Q6 : B    Q7 : C

SECTION 2 — Injections SQL
Q8 : B    Q9 : C    Q10 : B   Q11 : B   Q12 : B

SECTION 3 — Cross-Site Scripting (XSS)
Q13 : B   Q14 : C   Q15 : B   Q16 : B   Q17 : B   Q18 : A

SECTION 4 — RGPD et données personnelles
Q19 : C   Q20 : B   Q21 : C   Q22 : B   Q23 : B   Q24 : C

SECTION 5 — Protections navigateur
Q25 : C   Q26 : C   Q27 : B   Q28 : A   Q29 : B   Q30 : B

SECTION 6 — Concepts clés et Principes Security by Design
Q31 : B   Q32 : B   Q33 : B   Q34 : B   Q35 : B

SECTION 7 — Injections avancées (Path Traversal, Command, SSTI)
Q36 : C   Q37 : B   Q38 : B   Q39 : B   Q40 : A   Q41 : B

SECTION 8 — Vulnerabilités d'accès et CSRF
Q42 : B   Q43 : B   Q44 : B   Q45 : B   Q46 : A

SECTION 9 — Authentification sécurisée et Mass Assignment
Q47 : B   Q48 : C   Q49 : A   Q50 : C   Q51 : B   Q52 : B

SECTION 10 — Protections applicatives (Rate Limiting, SAST/DAST)
Q53 : B   Q54 : A   Q55 : A   Q56 : A   Q57 : B

SECTION 11 — Validation et Sanitization des entrées
Q58 : B   Q59 : B   Q60 : B   Q61 : B

SECTION 12 — Sécurité des APIs et authentification
Q62 : B   Q63 : B   Q64 : B   Q65 : B

SECTION 13 — Cryptographie et chiffrement
Q66 : B   Q67 : B   Q68 : C   Q69 : A

SECTION 14 — Gestion des erreurs et logging sécurisé
Q70 : B   Q71 : B   Q72 : B   Q73 : C

SECTION 15 — Contrôle d'accès et autorisation
Q74 : B   Q75 : B
```

---

## 🎯 CORRIGÉ DÉTAILLÉ PAR QUESTION

### SECTION 1 : Triade CIA

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q1** | **B** | Confidentialité = données accessibles uniquement aux personnes autorisées (contrôle d'accès, authentification, chiffrement) | seance1.md : 1.1.1 |
| **Q2** | **C** | AES-256-GCM est l'algorithme recommandé en 2026 pour le chiffrement au repos. DES et RC4 sont obsolètes ; MD5 est un hash, pas un chiffrement. | seance1.md : 1.1.1 (Chiffrement au repos) |
| **Q3** | **C** | Une attaque DDoS (déni de service) viole principalement la **Disponibilité** — les services ne sont pas accessibles. | seance1.md : 1.1.1 (Disponibilité) |
| **Q4** | **B** | HMAC = Hash-based Message Authentication Code. Combine une fonction de hash et une clé secrète pour assurer l'**authentification ET l'intégrité**. | seance1.md : 1.1.1 (Intégrité) |
| **Q5** | **A** | En RBAC (Role-Based Access Control), le champ `role` détermine les droits d'accès côté serveur. Il ne doit jamais être utilisé uniquement pour masquer/afficher l'UI. | seance1.md : 1.1.1 & seance2.md : 2.2.0 |
| **Q6** | **B** | Intégrité = garantir que les données ne sont pas modifiées sans autorisation. Modifier une BDD sans autorisation (B) viole l'intégrité. | seance1.md : 1.1.1 (Intégrité) |
| **Q7** | **C** | Couverture CIA : **C couvre tous les trois** — Chiffrement (confidentialité), signatures numériques (intégrité), réplication (disponibilité). | seance1.md : 1.1.1 (Triade CIA intégrée) |

---

### SECTION 2 : Injections SQL

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q8** | **B** | Injection SQL = **exécution de code SQL arbitraire**, permettant accès et modification des données en BDD. C'est le risque principal. | seance1.md : 1.4.1 |
| **Q9** | **C** | Meilleure méthode = **requêtes paramétrées / prepared statements** (ORM SQLAlchemy ou `?` placeholders). Cela sépare code et données. | seance1.md : 1.4.5 |
| **Q10** | **B** | `--` est le commentaire SQL standard (commentaire jusqu'à fin de ligne). Il transforme `WHERE ... AND password='...'` en commentaire ignoré. | seance1.md : 1.4.3 (Exploitation pratique) |
| **Q11** | **B** | Payload `1 OR 1=1 --` : l'expression `1=1` est toujours vraie, affichant tous les utilisateurs. Les alternatives ne produisent pas le même effet. | seance1.md : 1.4.2–1.4.3 (Technique classique) |
| **Q12** | **B** | Les requêtes paramétrées traitent les entrées utilisateur comme **données**, jamais comme **code SQL exécutable**. La séparation code/données est la défense fondamentale. | seance1.md : 1.4.5 (Prévention) |

---

### SECTION 3 : Cross-Site Scripting (XSS)

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q13** | **B** | **Reflected XSS** = payload dans l'URL, immédiatement reflété dans la réponse HTTP (non stocké). Non-persistant. | seance1.md : 1.5.1 (Reflected XSS) |
| **Q14** | **C** | `HttpOnly` empêche JavaScript d'accéder au cookie via `document.cookie`. C'est essentiel pour les cookies de session. | seance1.md : 1.1.1 (Authentification forte : cookies `HttpOnly`) |
| **Q15** | **B** | Échappement HTML : `<` → `&lt;` ; `>` → `&gt;`. Les alternatives `\<`, `%3C`, `[LT]` sont incorrectes. | seance1.md : 1.5.3 (Échappement contextuel) |
| **Q16** | **B** | **Sanitization** (via Bleach) supprime les attributs dangereux (`onerror`, `onload`, `onclick`). Validation d'entrée seule est insuffisante. | seance1.md : 1.5.3 (Sanitization avec bleach) |
| **Q17** | **B** | **Stored XSS** = le script malveillant est **sauvegardé en base de données** et réexécuté à chaque consultation. C'est la forme persistante la plus grave. | seance1.md : 1.5.1 (Stored XSS) |
| **Q18** | **A** | Jinja2 avec **auto-escaping désactivé** est vulnérable : `{{ user_input }}` exécute du code si non échappé. Thymeleaf/EJS/Nunjucks ont auto-escaping par défaut. | seance1.md : 1.5.2 (Template engines) |

---

### SECTION 4 : RGPD et données personnelles

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q19** | **C** | Principe de **Minimisation** (Article 5) = collecter le **strict nécessaire** seulement. Réduit la surface de données volées. | seance1.md : 1.2.1 (Minimisation) |
| **Q20** | **B** | Délai de notification CNIL = **72 heures** après découverte d'une fuite de données personnelles présentant un risque. | seance1.md : 1.2.1 (Violation de données) & seance2.md : 2.10 |
| **Q21** | **C** | Recommandé pour mots de passe : **bcrypt / Argon2**. Algorithmes lents, résistant aux attaques GPU/ASIC. MD5 et SHA-256 sont trop rapides (OWASP/NIST). | seance2.md : 2.5 (Stockage des mots de passe) |
| **Q22** | **B** | **Privacy by Design** = intégrer la protection des données dès la **conception**, pas en ajout tardif (Article 25 RGPD). | seance1.md : 1.2.1 (Privacy by Design) |
| **Q23** | **B** | **Droit à la portabilité** = l'utilisateur peut demander une copie de ses données dans un format structuré (Article 20 RGPD). Obligation légale. | seance1.md : 1.2.1 (Droit à la portabilité) |
| **Q24** | **C** | **Limitation de conservation** : les données ne doivent être conservées que **le temps nécessaire** à la finalité du traitement. Article 5 RGPD. | seance1.md : 1.2.1 (Principes de conservation) |

---

### SECTION 5 : Protections navigateur

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q25** | **C** | **Same-Origin Policy (SOP)** = mécanisme du navigateur empêchant scripts d'une origine d'accéder aux données d'une autre origine. Isolation automatique. | seance1.md : 1.6.1 (Same-Origin Policy) |
| **Q26** | **C** | `SameSite=Strict` offre la **meilleure protection CSRF**, mais peut bloquer certains parcours légitimes depuis liens entrants. | seance2.md : 2.1.3 (Détail des modes SameSite) |
| **Q27** | **B** | `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` = **violation directe** de la spécification CORS. Navigateur doit rejeter. | seance1.md : 1.6.2 (Configuration dangereuse) |
| **Q28** | **A** | **Content-Security-Policy (CSP)** = whitelist de sources autorisées pour ressources. Peut bloquer scripts d'origines non autorisées. | seance1.md : 1.6.3 (Content Security Policy) |
| **Q29** | **B** | **HSTS** (HTTP Strict-Transport-Security) = header qui **force le navigateur à n'utiliser que HTTPS**, bloquant les downgrade attacks. | seance1.md : 1.6.4 (HSTS) |
| **Q30** | **B** | **`X-Frame-Options: DENY`** empêche une page d'être affichée dans une iframe (iframe embedding). Défense contre le clickjacking. | seance1.md : 1.6.5 (Clickjacking) |

---

### SECTION 6 : Concepts clés et Principes Security by Design

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q31** | **B** | **CVSS v3.1** = standard pour évaluer et noter la gravité des vulnérabilités sur une échelle de 0 à 10. Scores : Faible (0.1–3.9), Moyen (4–6.9), Élevé (7–8.9), Critique (9–10). | seance1.md : 1.1.4 (CVSS Scoring System) |
| **Q32** | **B** | **Least Privilege** (Moindre Privilège) = accorder **uniquement les droits strictement nécessaires**. L'un des 6 principes Security by Design. | seance1.md : 1.1.3 (Principes Security by Design) |
| **Q33** | **B** | **Surface d'attaque** = ensemble des **points d'entrée** susceptibles d'être exploités : formulaires, URLs, headers HTTP, APIs, dépendances, infrastructure. | seance1.md : 1.1.2 (Surface d'attaque) |
| **Q34** | **B** | **Secure by Default** = la sécurité doit être **activée par défaut**, pas configurable optionnellement. Configuration sûre "out of the box". | seance1.md : 1.1.3 (Principes Security by Design) |
| **Q35** | **B** | **Defense in Depth** = empiler **plusieurs couches de défense indépendantes** (au lieu d'une seule). Si une couche échoue, les autres les arrêtent. | seance1.md : 1.1.3 (Principes Security by Design) |

---

### SECTION 7 : Injections avancées

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q36** | **C** | **Path Traversal** (Traversée de répertoire) = utiliser `../` pour remonter la hiérarchie et accéder à fichiers en dehors du répertoire autorisé. Exemple : `/download?file=../../etc/passwd`. | seance1.md : 1.7.1 (Path Traversal) |
| **Q37** | **B** | `shell=True` + f-string = l'utilisateur peut injecter des commandes via les séparateurs `;`, `\|`, `&&`, etc. `ping localhost; cat /etc/passwd` exécute deux commandes. | seance1.md : 1.7.2 (Exemple vulnérable) |
| **Q38** | **B** | **SSTI** (Server-Side Template Injection) = injection de code dans un template côté serveur (Jinja2, etc.), permettant l'**exécution de code arbitraire (RCE)** complet. | seance2.md : 2.4.1 & 2.4.2 (Exploitation — Du RCE complet) |
| **Q39** | **B** | Prévention de Command Injection : utiliser `subprocess.run(['ping', '-c', '1', host], shell=False)`. Liste d'arguments + `shell=False` = pas d'interprétation shell. | seance1.md : 1.7.2 (Défense — pourquoi shell=False protège) |
| **Q40** | **A** | Path Traversal classique : `../../../etc/passwd` remonte 3 niveaux depuis `/var/www/app/uploads/` pour accéder à `/etc/passwd`. | seance1.md : 1.7.1 (Exploitation pratique) |
| **Q41** | **B** | Prévention de Path Traversal : utiliser des chemins **absolus** et **vérifier qu'ils restent dans le répertoire autorisé** (canonicalization). Ne pas bloquer juste `../`. | seance1.md : 1.7.1 (Défense) |

---

### SECTION 8 : Vulnerabilités d'accès et CSRF

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q42** | **B** | **Authentification** (AuthN) = vérifier l'**identité** (qui êtes-vous ?) ; **Autorisation** (AuthZ) = vérifier les **droits** (que pouvez-vous faire ?). Concepts **indépendants** et **complémentaires**. | seance2.md : 2.2.0 (Authentification vs Autorisation) |
| **Q43** | **B** | **IDOR** (Insecure Direct Object Reference) = accès **non autorisé** à des ressources via une **référence prédictible** (ID séquentiel) **sans vérifier la propriété**. Exemple : `/api/orders/5` accessible par tout utilisateur. | seance2.md : 2.2.1–2.2.2 (IDOR) |
| **Q44** | **B** | **CSRF** (Cross-Site Request Forgery) = le **navigateur envoie automatiquement les cookies de session**, même pour requêtes initiées depuis un **autre site**. L'attaquant ne connaît jamais le cookie, c'est le navigateur qui le fournit. | seance2.md : 2.1.1 (Pourquoi CSRF est-il possible) |
| **Q45** | **B** | Vérification IDOR : **comparer l'ID de la ressource avec l'identifiant de session de l'utilisateur authentifié** (propriété vérifiée côté serveur). | seance2.md : 2.2.2 (Prévention IDOR) |
| **Q46** | **A** | Blocage CSRF : utiliser un **token CSRF unique généré côté serveur** et inclus dans le formulaire. Le navigateur ne l'envoie pas automatiquement depuis un autre site. | seance2.md : 2.1.2 (Protection CSRF Token) |

---

### SECTION 9 : Authentification sécurisée et Mass Assignment

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q47** | **B** | **Mass Assignment** = l'application accepte **tous les champs POST/JSON sans filtrage**, permettant à l'attaquant d'injecter des champs sensibles comme `is_admin=true`. | seance2.md : 2.3.1 (Mass Assignment) |
| **Q48** | **C** | Recommandé pour hasher mots de passe : **bcrypt ou Argon2**. Coût configurable, résistant GPU/ASIC. **MD5 et SHA-256 sont trop rapides** → brute force trivial. **Base64 n'est pas du hashage** (décodable). | seance2.md : 2.5 (Hiérarchie de mauvaises à bonnes pratiques) |
| **Q49** | **A** | **Session Fixation** = attaquant fixe un identifiant de session et la victime l'utilise (puis se connecte, le fixant). Prévention = **régénérer complètement la session après login**. | seance2.md : 2.6.2 (SessionManager.login_user) |
| **Q50** | **C** | `SameSite=Strict` offre la **meilleure protection CSRF** (cookie jamais envoyé en cross-site), mais peut casser les liens entrants. `Lax` = bon compromis par défaut. | seance2.md : 2.1.3 (Détail des modes SameSite) |
| **Q51** | **B** | Prévention Mass Assignment avec Marshmallow : **whitelist explicite** des champs autorisés dans le schéma (ex. `fields = ['username', 'email']`). Refuser les champs non déclarés. | seance2.md : 2.3.2 (Whitelist avec Marshmallow) |
| **Q52** | **B** | **Réutilisation de session** : attaquant usurpe l'identité et accède aux données privées de la victime. D'où l'importance de la régénération post-login et du `HttpOnly`. | seance2.md : 2.6 (Sécurité des sessions) |

---

### SECTION 10 : Protections applicatives

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q53** | **B** | **Rate limiting** = limiter le nombre de requêtes par minute/heure sur un endpoint. Sur `/login` : 5 tentatives/min. Bloque le brute force, l'énumération. | seance2.md : 2.7 (Flask-Limiter) |
| **Q54** | **A** | **SAST** (Static Analysis) = analyse le **code source statiquement** (Bandit, Semgrep). **DAST** (Dynamic Analysis) = teste l'**application en cours d'exécution** (ZAP, Burp). Deux approches complémentaires. | seance2.md : 2.8 (Outils Python pour le SDLC sécurisé) |
| **Q55** | **A** | **Token bucket** : chaque requête consomme un jeton d'un seau qui se **remplit à un taux fixe**. Quand le seau est vide, les requêtes sont rejetées. Permet les rafales. | seance2.md : 2.7 (Algorithmes rate limiting) |
| **Q56** | **A** | Outils **SAST** pour Python : **Bandit** (sécurité) ou **Semgrep** (règles personnalisées). Outils **DAST** : ZAP, Burp Suite (tests dynamiques). | seance2.md : 2.8 (Outils) |
| **Q57** | **B** | Complémentarité : **SAST décèle les problèmes de code statique** (patterns dangereux) ; **DAST teste le comportement dynamique et les interactions runtime**. Ensemble = couverture complète. | seance2.md : 2.8 (Intégration SDLC) |

---

### SECTION 11 : Validation et Sanitization des entrées

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q58** | **B** | **Validation** = vérifie si les données sont **acceptables** (format, plage) ; **Sanitization** = **nettoie** les données dangereuses. Deux étapes distinctes et complémentaires. | seance1.md : 1.5.3 (Validation vs Sanitization) |
| **Q59** | **B** | **Liste blanche (whitelist)** = accepter **uniquement** ce qui est autorisé = approche **la plus sûre**. Blacklist = bloquer ce qu'on connaît = incomplète et contournable. | seance1.md : 1.5.3 (Whitelist vs Blacklist) |
| **Q60** | **B** | Danger de **blacklist** = attaquants peuvent contourner avec **encodages alternatifs** (`%3C`, `&#60;`, `\x3c`) ou **caractères non prévus**. Blacklist est jamais exhaustive. | seance1.md : 1.5.3 (Limitations de la blacklist) |
| **Q61** | **B** | **Bleach avec `strip=True`** = supprime les balises non autorisées tout en **gardant le texte**. Approche sûre pour sanitization HTML. | seance1.md : 1.5.3 (Sanitization avec bleach) |

---

### SECTION 12 : Sécurité des APIs et authentification

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q62** | **B** | API REST sécurisée : **API Keys ou Bearer tokens (JWT)** avec **HTTPS obligatoire**. Jamais envoyer de credentials en GET. | seance2.md : 2.9 (Sécurité API) |
| **Q63** | **B** | **JWT** (JSON Web Token) = token **signé cryptographiquement** contenant des claims (revendications) sur l'utilisateur. Stateless, portable. | seance2.md : 2.9 (JWT) |
| **Q64** | **B** | Risque localStorage : **attaques XSS peuvent voler le JWT**. Préférer **cookie HttpOnly** (inaccessible à JavaScript). | seance2.md : 2.9 (Stockage JWT) |
| **Q65** | **B** | **`Access-Control-Allow-Origin`** = header CORS déclare les **origines autorisées** à faire des requêtes cross-origin. Exemple : `https://trusted.com`. | seance1.md : 1.6.2 (CORS) |

---

### SECTION 13 : Cryptographie et chiffrement

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q66** | **B** | **Chiffrement symétrique** = une clé unique partagée (AES). **Asymétrique** = paire clé publique/privée (RSA, ECDSA). Symétrique = rapide ; asymétrique = infrastructure clés. | seance1.md : 1.1.1 (Chiffrement) |
| **Q67** | **B** | **TLS/SSL** = **chiffre les données en transit** ET **authentifie le serveur** via un certificat. Échange de clés sécurisé. Fondation HTTPS. | seance1.md : 1.1.1 (SSL/TLS) |
| **Q68** | **C** | Algorithme **compromis** (cassable) : **MD5** n'est PAS un chiffrement (c'est un hash) — les vraies cibles compromises sont DES, RC4 ou certificats RSA-768. AES-256 et TLS 1.3 restent sûrs. | seance1.md : 1.1.1 (Algorithmes compromis) |
| **Q69** | **A** | Hashs (MD5, SHA-1) ne sont **pas réversibles par design** — on ne peut pas récupérer les données originales. Donc inutiles pour **chiffrer**, seulement pour **vérifier l'intégrité**. | seance1.md : 1.1.1 (Hashs vs chiffrement) |

---

### SECTION 14 : Gestion des erreurs et logging sécurisé

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q70** | **B** | Danger des messages d'erreur détaillés : attaquants exploitent les **stack traces, versions de frameworks, chemins système** pour affiner les attaques. | seance2.md : 2.10 (Error handling) |
| **Q71** | **B** | Gestion production : afficher un **message générique à l'utilisateur** (`"Erreur interne"`) et **logger les détails côté serveur en secret**. Limite la fuite d'info. | seance2.md : 2.10 (Custom error pages) |
| **Q72** | **B** | **Log poisoning** = attaquant **injecte du contenu malveillant dans les logs** (ex. XSS dans un log consulté via un dashboard) pour les corrompre ou tromper les admins. | seance2.md : 2.10 (Log poisoning) |
| **Q73** | **C** | **JAMAIS logguer en clair** : mots de passe, tokens d'authentification, données de paiement (PAN, CVV), clés API. Risque = exposition via accident de log partagé. | seance2.md : 2.10 (Sensitive data logging) |

---

### SECTION 15 : Contrôle d'accès et autorisation

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q74** | **B** | **RBAC** (Role-Based Access Control) = contrôler l'accès **basé sur les rôles** assignés (admin, user, moderator, etc.). Rôle = ensemble de permissions. | seance2.md : 2.2.0 (RBAC) |
| **Q75** | **B** | Danger du contrôle côté **client uniquement** : attaquants **contournent les vérifications JavaScript** (bypasser l'UI). **Contrôle serveur obligatoire**. L'UI est juste pour UX. | seance2.md : 2.2.2 (Vérification serveur obligatoire) |

---

## 📊 BARÈME DE NOTATION

### Par réponse

- **Réponse correcte** : 1 point
- **Réponse incorrecte** : 0 point
- **Pas de réponse** : 0 point

**Total** : 75 points

### Conversion sur 20

```
Formule de conversion : (Points obtenus / 75) × 20

Exemples :
- 75/75 = 20/20 (100%)
- 67/75 = 17.9/20 (≈89%)
- 60/75 = 16/20 (≈80%)
- 52/75 = 13.9/20 (≈69%)
- 38/75 = 10.1/20 (50% — seuil critique)
- 25/75 = 6.7/20 (≈33% — insuffisant)
```

### Grille de notation alternative (sur 10)

```
Conversion sur 10 : (Points obtenus / 75) × 10

- 68–75 : 9.1–10/10 (Excellent)
- 60–67 : 8–8.9/10 (Très bon)
- 52–59 : 6.9–7.9/10 (Bon)
- 45–51 : 6–6.8/10 (Acceptable)
- 38–44 : 5–5.9/10 (Juste suffisant)
- <38 : <5/10 (Insuffisant)
```

---

## 📈 DISTRIBUTION PAR THÈME

| Thème | Questions | # Q | Poids % | Taux réussite attendu |
|-------|-----------|-----|---------|----------------------|
| **Triade CIA** | Q1–Q7 | 7 | 9.3% | ≥90% (fondamentaux) |
| **Injections SQL** | Q8–Q12 | 5 | 6.7% | ≥85% |
| **XSS** | Q13–Q18 | 6 | 8% | ≥80% |
| **RGPD** | Q19–Q24 | 6 | 8% | ≥75% (aspect légal) |
| **Protections nav** | Q25–Q30 | 6 | 8% | ≥70% |
| **Concepts & Principes** | Q31–Q35 | 5 | 6.7% | 60–75% (intermédiaire) |
| **Injections avancées** | Q36–Q41 | 6 | 8% | 55–70% |
| **Accès & CSRF** | Q42–Q46 | 5 | 6.7% | 50–70% |
| **Auth & Mass Assignment** | Q47–Q52 | 6 | 8% | 50–65% |
| **Protections appli** | Q53–Q57 | 5 | 6.7% | 60–75% |
| **Validation & Sanitization** | Q58–Q61 | 4 | 5.3% | 60–75% (intermédiaire) |
| **Sécurité des APIs** | Q62–Q65 | 4 | 5.3% | 55–70% |
| **Cryptographie** | Q66–Q69 | 4 | 5.3% | 55–70% |
| **Gestion erreurs & logging** | Q70–Q73 | 4 | 5.3% | 55–70% |
| **Contrôle d'accès** | Q74–Q75 | 2 | 2.7% | 60–75% |
| **TOTAL** | — | **75** | **100%** | — |

---

## 📋 INTERPRÉTATION PAR PERFORMANCE

| Plage de points | Plage % | Interprétation | Recommandation |
|---|---|---|---|
| **62–75** | **83–100%** | ✅ **Excellent** — Maîtrise complète | Étudiant prêt pour examen/pratique avancée |
| **54–61** | **72–81%** | ✅ **Très bon** — Bonne compréhension | Quelques lacunes mineures à revoir |
| **43–53** | **57–71%** | ⚠️ **Bon** — Acquis solides | Réviser certains modules (voir analyse par section) |
| **37–42** | **49–56%** | ⚠️ **Juste suffisant** — Seuil critique | **Demander une révision guidée avant examen** |
| **24–36** | **32–48%** | ❌ **Insuffisant** — Gaps importants | **Revoir l'ensemble du cours + rattrapage obligatoire** |
| **<24** | **<32%** | ❌ **Très insuffisant** — Compréhension minimale | **Entretien avec l'enseignant + soutien intensif** |

---

## 🔍 ANALYSE PAR SECTION (pour feedback étudiant)

### Si taux de réussite < attendu :

**Sections 1–5 (Fondamentaux)** — Taux attendu ≥75%
- Si <70% : réviser seance1.md modules 1.1 (CIA) et 1.4–1.6 (Injections, XSS, protections)
- Points de focus : concepts de base CIA, requêtes paramétrées, échappement HTML

**Sections 6–10 (Intermédiaire)** — Taux attendu 60–75%
- Si <55% : revoir seance1.md modules 1.1.3 (Principes), 1.7 (Path Traversal, Command) + seance2.md modules 2.1–2.3 (CSRF, IDOR) et 2.4 (SSTI)
- Points de focus : principes Security by Design, injections système, templates, autorisation, sécurité de session

**Sections 11–15 (Avancé)** — Taux attendu 55–70%
- Si <50% : revoir seance2.md modules 2.8–2.10 (SAST/DAST, cryptographie, logging sécurisé) + contextes d'API et gestion des erreurs
- Points de focus : validation/sanitization, authentification API, hashage et chiffrement, logs et erreurs

---

## 📝 REMARQUES PÉDAGOGIQUES

### Notes générales

- **Temps moyen par question** : 25 min / 75 Q ≈ **20 secondes/Q** (compact pour 4 choix)
- **Distribution équilibrée** : chaque thème représente 2.7–9.3% de la notation
- **Progression pédagogique** : Sections 1–5 (basiques) → Sections 6–10 (appliquées) → Sections 11–15 (avancées/complémentaires)

### Premiers signes d'alerte

| Indicateur | Action |
|-----------|--------|
| >30% échouent Q1–Q7 (Triade CIA) | Renforcer les fondamentaux ; reprise des concepts de base |
| >30% échouent Q31–Q35 (Principes) | Ajouter une séance de review des 6 principes Security by Design |
| >40% échouent Q36–Q41 (Injections avancées) | Proposer lab pratique sur Path Traversal & Command Injection |
| >50% échouent Q42–Q46 (Accès & CSRF) | Revoir CSRF vs IDOR ; session de clarification nécessaire |
| >40% échouent Q58–Q65 (Validation, APIs, Crypto) | Contenu plus avancé ; proposer TP pratique sur SAST/DAST |
| Corrélation avec Seance 2 Quiz | Indiquer que la compréhension du SDLC sécurisé est plus faible |

### Post-session (à remplir après 1ère administration)

- **Questions fréquemment manquées** : Q__ (>20% d'erreur)
- **Taux de réussite global** : ___%
- **Écarts inter-groupes** : À analyser
- **Ajustements recommandés** : À noter

---

## 🔐 DISTRIBUTION ET ARCHIVAGE

**Accès restreint** :
- ✅ Partagé via Moodle / plateforme institutionnelle (enseignants uniquement)
- ❌ Pas de circulation auprès des étudiants avant clôture officielle
- ✅ Conservé pour analyse comparative entre sessions (archive pédagogique)

**Dates importantes** :
- Quiz administré : [À remplir]
- Résultats publiés : [À remplir]
- Feedback distribué : [À remplir]

---


