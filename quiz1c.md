# Quiz 1.C — Fondamentaux de la sécurité web

**Durée : 25 min — Pondération : 10% de la note finale**  
**Format :** QCM, une seule bonne réponse par question  
**Remarque :** Ce quiz (36 questions) couvre l'intégrité des 3 séances, améliorant la couverture pédagogique : principes Security by Design, injections avancées (Path Traversal, Command Injection, SSTI), CSRF, IDOR, authentification sécurisée, sessions, rate limiting, et processus SDLC (SAST/DAST).

---

## 📝 Questions

### SECTION 1 : Triade CIA (7 questions)

**Q1.** Laquelle de ces déclarations décrit correctement la **Confidentialité** ?
- A) Garantir que les données ne sont pas modifiées sans autorisation
- B) Garantir que les données ne sont accessibles qu'aux personnes autorisées
- C) Garantir que les services sont disponibles 24/7
- D) Mettre à jour les patches de sécurité mensuellement

**Q2.** Quel algorithme de chiffrement est considéré comme **sûr** pour chiffrer les données au repos en 2026 ?
- A) DES (Data Encryption Standard)
- B) RC4
- C) AES-256-GCM
- D) MD5

**Q3.** Une attaque DDoS viole principalement lequel des trois piliers CIA ?
- A) Confidentialité
- B) Intégrité
- C) Disponibilité
- D) Tous les trois

**Q4.** Quel est le principal objectif du code d'authentification **HMAC** ?
- A) Assurer la confidentialité des données
- B) Assurer l'authentification ET l'intégrité avec une clé secrète
- C) Compresser les données
- D) Accélérer les communications réseau

**Q5.** Dans RBAC (Role-Based Access Control), quel est le rôle du champ `role` dans une base de données ?
- A) Déterminer les droits d'accès de l'utilisateur
- B) Enregistrer le nom complet de l'utilisateur
- C) Tracer l'historique des accès
- D) Chiffrer les données sensibles

**Q6.** Lequel de ces scénarios viole le pilier d'**Intégrité** ?
- A) Un attaquant intercepte une communication SSL/TLS
- B) Un attaquant modifie des données en base de données sans autorisation
- C) Un serveur est inaccessible pendant 2 heures
- D) Un utilisateur oublie son mot de passe

**Q7.** Quel ensemble de mesures couvre les trois piliers CIA dans un système bien conçu ?
- A) Chiffrement, authentification, rate limiting
- B) Contrôle d'accès, certificats SSL, logs
- C) Chiffrement (confidentialité), signatures numériques (intégrité), réplication (disponibilité)
- D) Pare-feu, antivirus, mises à jour

---

### SECTION 2 : Injections SQL (5 questions)

**Q8.** Quel est le **principal risque** d'une injection SQL ?
- A) Ralentissement des serveurs
- B) Exécution de code SQL arbitraire et accès/modification des données
- C) Saturation de la bande passante
- D) Perte de fichiers sur le disque dur

**Q9.** Quelle est la meilleure méthode pour prévenir une injection SQL en Python ?
- A) Valider les entrées avec regex
- B) Mettre en minuscule l'entrée utilisateur
- C) Utiliser des requêtes paramétrées / prepared statements
- D) Limiter la longueur des chaînes à 10 caractères

**Q10.** Quel est le commentaire SQL qui permet de contourner la vérification du mot de passe ?

```sql
SELECT * FROM users WHERE email='admin@test.com' _______ AND password='...'
```
- A) `/**/`
- B) `--`
- C) `#`
- D) `//`

**Q11.** Considérez le code vulnérable : `query = f"SELECT * FROM users WHERE id={user_id}"`. Quel payload d'injection SQL affiche tous les utilisateurs ?
- A) `user_id = "1"; DROP TABLE users; --`
- B) `user_id = "1 OR 1=1 --"`
- C) `user_id = "1 UNION SELECT password FROM users --"`
- D) `user_id = "1 AND password LIKE '%'"`

**Q12.** Une requête SQL paramétrée empêche l'injection SQL car :
- A) Le serveur ignorera les caractères spéciaux
- B) Les entrées utilisateur sont traitées comme données, pas comme code SQL exécutable
- C) Le chiffrement est appliqué automatiquement
- D) Les connexions réseau deviennent plus lentes

---

### SECTION 3 : Cross-Site Scripting (XSS) (6 questions)

**Q13.** Quel type de XSS est reflété immédiatement dans la réponse HTTP sans être stocké ?
- A) Stored XSS
- B) Reflected XSS
- C) DOM-based XSS
- D) Blind XSS

**Q14.** Quel flag du cookie de session empêche l'accès via JavaScript ?
- A) `Secure`
- B) `SameSite`
- C) `HttpOnly`
- D) `Domain`

**Q15.** Quel échappement est approprié pour afficher du texte dans une balise HTML ?
- A) `<` → `\<`
- B) `<` → `&lt;`
- C) `<` → `%3C`
- D) `<` → `[LT]`

**Q16.** Un payload XSS `<img src=x onerror=alert(1)>` peut être bloqué par :
- A) Validation d'entrée uniquement
- B) Sanitization (suppression des attributs `onerror`)
- C) Rate limiting
- D) Authentification forte

**Q17.** Qu'est-ce que le **Stored XSS** (XSS stocké) ?
- A) Une attaque où le script est reflété dans l'URL
- B) Une attaque où le script malveillant est sauvegardé en base de données et exécuté à chaque consultation
- C) Une attaque qui modifie les fichiers statiques du serveur
- D) Une attaque qui nécessite l'installation de malware sur l'ordinateur

**Q18.** Quel template engine est particulièrement vulnérable aux injections si la variable utilisateur n'est pas échappée ?

```jinja
Bonjour {{ user_input }}
```
- A) Jinja2 (Flask) avec auto-escaping désactivé
- B) Thymeleaf (Spring)
- C) EJS (Node.js) avec auto-escaping
- D) Nunjucks (Node.js)

---

### SECTION 4 : RGPD et données personnelles (6 questions)

**Q19.** Quel est le principe RGPD fondamental qui impose de collecter le **minimum** de données ?
- A) Licéité
- B) Limitation de la conservation
- C) Minimisation
- D) Intégrité

**Q20.** Après une fuite de données personnelles, quel est le délai de notification à la CNIL ?
- A) 24 heures
- B) 72 heures
- C) 7 jours
- D) 30 jours

**Q21.** Quel algorithme de hashage est recommandé pour stocker les mots de passe ?
- A) MD5
- B) SHA-256
- C) bcrypt / Argon2
- D) Base64

**Q22.** « Privacy by Design » signifie :
- A) Ajouter des mesures de confidentialité après le déploiement
- B) Intégrer la protection des données dès la conception
- C) Ignorer le RGPD pendant le développement
- D) Chiffrer uniquement les données sensibles

**Q23.** Quel est le droit de l'utilisateur qui oblige une entreprise à fournir une copie de toutes les données stockées à son sujet ?
- A) Droit d'oubli
- B) Droit à la portabilité des données
- C) Droit de rectification
- D) Droit d'opposition

**Q24.** Combien de temps maximum les données personnelles peuvent-elles être conservées sans justification légitime selon le RGPD ?
- A) Illimitée
- B) 1 an
- C) La durée nécessaire à la finalité du traitement
- D) 10 ans

---

### SECTION 5 : Protections navigateur (6 questions)

**Q25.** Quel mécanisme empêche les scripts d'une autre origine d'accéder aux données ?
- A) CORS (en tant que header de réponse)
- B) `Content-Security-Policy`
- C) La **Same-Origin Policy** du navigateur
- D) `X-Frame-Options`

**Q26.** Quel mode de **SameSite cookie** offre la meilleure protection CSRF mais peut bloquer les liens entrants ?
- A) `None`
- B) `Lax`
- C) `Strict`
- D) `Unsecured`

**Q27.** Quel est le problème de `Access-Control-Allow-Origin: *` combiné à `credentials: true` ?
- A) Aucun problème
- B) Violation directe de la spécification CORS
- C) Ralentit les requêtes
- D) Augmente la consommation mémoire

**Q28.** La **Content-Security-Policy (CSP)** peut bloquer :
- A) Scripts d'origines non autorisées
- B) Uniquement les requêtes HTTPS
- C) Les fichiers trop volumineux
- D) Les connexions VPN

**Q29.** Qu'est-ce que **HSTS** (HTTP Strict-Transport-Security) ?
- A) Un protocole de chiffrement alternatif à SSL/TLS
- B) Un header qui force le navigateur à n'utiliser que HTTPS
- C) Une méthode pour valider les certificats SSL
- D) Un type de pare-feu applicatif

**Q30.** Quel header protège une page contre les attaques de **clickjacking** ?
- A) `X-Content-Type-Options: nosniff`
- B) `X-Frame-Options: DENY`
- C) `Strict-Transport-Security`
- D) `Access-Control-Allow-Origin`

---

### SECTION 6 : Concepts clés et Principes Security by Design (5 questions)

**Q31.** Lequel de ces énoncés décrit correctement le **CVSS v3.1** ?
- A) Un type de vulnérabilité critique de réseau
- B) Un standard pour évaluer et noter la gravité des vulnérabilités (score 0–10)
- C) Un algorithme de chiffrement asymétrique
- D) Une politique d'authentification multi-facteur

**Q32.** Le principe Security by Design « **Least Privilege** » signifie :
- A) Donner l'accès administrateur à tous les utilisateurs
- B) Accorder uniquement les droits strictement nécessaires à un utilisateur
- C) Minimiser les logs de sécurité
- D) Utiliser les mots de passe les plus simples possible

**Q33.** Qu'est-ce qu'une **surface d'attaque** en sécurité informatique ?
- A) La zone physique du serveur
- B) L'ensemble des points d'entrée (formulaires, APIs, ports) susceptibles d'être exploités
- C) Le nombre total d'utilisateurs connectés
- D) La vitesse des connexions réseau

**Q34.** Quel principe Security by Design préconise que la sécurité soit **activée par défaut** ?
- A) Defense in Depth
- B) **Secure by Default**
- C) Fail Secure
- D) Zero Trust

**Q35.** Le principe **Defense in Depth** signifie :
- A) Mettre une seule couche de sécurité très solide
- B) Empiler plusieurs couches de défense indépendantes pour réduire le risque
- C) Utiliser uniquement des outils cryptographiques
- D) Ignorer la sécurité au niveau du code

---

### SECTION 7 : Injections avancées (Path Traversal, Command Injection, SSTI) (6 questions)

**Q36.** Quelle vulnérabilité permet de traverser la hiérarchie des répertoires en utilisant `../` pour accéder à des fichiers sensibles ?
- A) Injection SQL
- B) Cross-Site Scripting
- C) **Path Traversal** (Traversée de répertoire)
- D) Command Injection

**Q37.** Pourquoi utiliser `shell=True` dans `subprocess.check_output(f"ping {host}", shell=True)` en Python est-il dangereux ?
- A) Cela ralentit les performances
- B) L'utilisateur peut injecter des commandes via des séparateurs comme `;` ou `|`
- C) Cela fonctionne uniquement sous Linux
- D) Cela consomme trop de mémoire

**Q38.** Qu'est-ce qu'une vulnérabilité **SSTI** (Server-Side Template Injection) ?
- A) Injection de balises HTML côté client (navigateur)
- B) Injection de code dans un template côté serveur, permettant l'exécution de code arbitraire (RCE)
- C) Injection de SQL dans une base de données
- D) Injection de JavaScript que le serveur réfléchit

**Q39.** Quel fonction Python peut aider à prévenir les injections de commandes ?
- A) Utiliser `os.system()` avec validation simples
- B) Utiliser `subprocess.run()` avec une liste d'arguments et `shell=False`
- C) Déactiver le shell de l'OS
- D) Aucune, les injections de commandes sont inévitables

**Q40.** Considérez un code qui serveille des fichiers dans `/var/www/app/uploads/`. Quel payload Path Traversal accède à `/etc/passwd` ?
- A) `../../../etc/passwd`
- B) `subdir/file.txt`
- C) `./uploads/file.txt`
- D) `file.txt|cat /etc/passwd`

**Q41.** Comment prévenir les vulnérabilités de Path Traversal ?
- A) Utiliser une regex pour valider les noms de fichiers
- B) Utiliser des chemins absolu et vérifier qu'ils restent dans le répertoire autorisé
- C) Bloquer uniquement `../`
- D) Faire confiance aux entrées utilisateur si elles contiennent des `/`

---

### SECTION 8 : Vulnerabilités d'accès et CSRF (5 questions)

**Q42.** Quelle est la différence fondamentale entre **Authentification** et **Autorisation** ?
- A) Ce sont deux termes synonymes
- B) **Authentification** = vérifier l'identité (qui êtes-vous ?) ; **Autorisation** = vérifier les droits (que pouvez-vous faire ?)
- C) Authentification s'applique uniquement aux administrateurs
- D) Autorisation est vérifiée avant l'authentification

**Q43.** Qu'est-ce qu'une vulnérabilité **IDOR** (Insecure Direct Object Reference) ?
- A) Une injection de commande système
- B) Accès non autorisé à des ressources via une référence directe prédictible sans vérifier la propriété
- C) Une authentification sans mot de passe
- D) Une fuite de session cookie via le réseau

**Q44.** **CSRF** (Cross-Site Request Forgery) exploite le fait que :
- A) Les mots de passe sont stockés en clair
- B) Le navigateur envoie automatiquement les cookies de session, même pour des requêtes initiées depuis un autre site
- C) Les bases de données ne sont pas chiffrées
- D) Les utilisateurs ne lisent pas les conditions d'utilisation

**Q45.** Un attaquant exploite une IDOR en accédant à `/user/profile/123`. Comment vérifier que l'ID 123 appartient à l'utilisateur actuel ?
- A) Vérifier que l'ID est un nombre entier
- B) Comparer l'ID avec l'identifiant de session de l'utilisateur authentifié
- C) Vérifier que la base de données contient cet ID
- D) Aucun contrôle n'est nécessaire si l'utilisateur est authentifié

**Q46.** Comment bloquer une attaque CSRF pour une requête POST qui modifie les données ?
- A) Utiliser un token CSRF (XSRF token) généré côté serveur et inclus dans le formulaire
- B) Bloquer toutes les requêtes POST depuis d'autres domaines
- C) Forcer HTTPS obligatoirement
- D) Ajouter un délai aléatoire à la réponse

---

### SECTION 9 : Authentification sécurisée et Mass Assignment (6 questions)

**Q47.** **Mass Assignment** se produit quand :
- A) Plusieurs utilisateurs se connectent simultanément
- B) L'application accepte tous les champs POST sans filtrage, permettant la modification de champs sensibles comme `is_admin`
- C) Le serveur refuse trop de connexions
- D) Le cache est saturé

**Q48.** Entre **MD5**, **SHA-256** et **bcrypt**, lequel est recommandé pour hasher les mots de passe en 2026 ?
- A) MD5 (résistant et rapide)
- B) SHA-256 (standard moderne)
- C) **bcrypt** ou **Argon2** (coût configurable, résistant aux attaques GPU/ASIC)
- D) Base64 (facile à implémenter)

**Q49.** Qu'est-ce qu'une **Session Fixation** et comment la prévenir ?
- A) L'attaquant fixe un identifiant de session et la victime l'utilise ; prévention : régénérer complètement la session après login
- B) C'est impossible à prévenir
- C) À résoudre uniquement avec HTTPS
- D) À traiter avec des cookies sans attribut Secure

**Q50.** Quel mode **SameSite** du cookie de session offre la meilleure protection **CSRF** mais peut bloquer certains accès légitimes ?
- A) `None`
- B) `Lax`
- C) **`Strict`**
- D) `Encrypted`

**Q51.** Comment prévenir une vulnérabilité **Mass Assignment** en utilisant Marshmallow (validation framework) ?
- A) Ne valider aucun champ
- B) Utiliser une **whitelist explicite** des champs autorisés dans le schéma
- C) Valider uniquement les champs numériques
- D) Utiliser un regex sur tous les champs

**Q52.** Quel est le risque si un attaquant réutilise un identifiant de session d'un autre utilisateur ?
- A) C'est impossible, les sessions sont toujours uniques
- B) L'attaquant peut usurper l'identité et accéder aux données privées de la victime
- C) Les logs seront corrompus
- D) Le serveur va créer un nouveau compte

---

### SECTION 10 : Protections applicatives (Rate Limiting, SAST/DAST) (5 questions)

**Q53.** **Rate limiting** sur un endpoint sensible comme `/login` sert à :
- A) Accélérer les connexions réussies
- B) Limiter le nombre de tentatives par minute pour bloquer les attaques par brute force
- C) Chiffrer automatiquement les mots de passe
- D) Ajouter un délai de réseau artificiel

**Q54.** Quelle est la différence entre **SAST** et **DAST** dans un SDLC sécurisé ?
- A) SAST analyse le code source statiquement ; DAST teste l'application en cours d'exécution
- B) Ce sont deux noms du même processus
- C) SAST ne détecte que les erreurs de syntaxe
- D) DAST ne fonctionne qu'en production

**Q55.** Un algorithme **rate limiting** peut utiliser une **token bucket**. Comment cela fonctionne-t-il ?
- A) Chaque requête consomme un jeton d'un seau qui se remplissait à un taux fixe
- B) Chaque requête ajoute un jeton au seau
- C) Les jetons ne se régénèrent jamais
- D) Le seau a une taille infinie

**Q56.** Quel outil est recommandé pour effectuer une analyse **SAST** (Static Application Security Testing) sur un dépôt Python ?
- A) Bandit ou Semgrep
- B) OWASP ZAP
- C) Burp Suite
- D) curl

**Q57.** Pourquoi les deux approches SAST et DAST sont-elles complémentaires ?
- A) SAST détecte tous les bugs, DAST détecte les problèmes de performance
- B) SAST décèle les problèmes de code statique ; DAST teste le comportement dynamique et les interactions
- C) Elles sont redondantes, une seule suffit
- D) SAST fonctionne uniquement en production

---

### SECTION 11 : Validation et Sanitization des entrées (4 questions)

**Q58.** Quelle est la différence entre **validation** et **sanitization** ?
- A) Ce sont deux termes synonymes
- B) **Validation** vérifie si les données sont acceptables ; **Sanitization** nettoie les données dangereuses
- C) Validation fonctionne côté serveur, sanitization côté client
- D) Sanitization empêche complètement les attaques XSS

**Q59.** Quel type de validation est le PLUS sûr pour accepter une entrée utilisateur ?
- A) Accepter tout ce qui n'est pas une liste noire de caractères dangereux
- B) Accepter UNIQUEMENT ce qui figure dans une **liste blanche** (whitelist)
- C) Faire confiance au type des données
- D) Valider avec une regex simple

**Q60.** Pourquoi utiliser une liste noire (blacklist) pour bloquer certains caractères est-elle dangereuse ?
- A) Les listes noires sont plus rapides que les listes blanches
- B) Les attaquants peuvent contourner la blacklist avec des encodages alternatifs ou des caractères non prévus
- C) Les listes noires facilitent les faux positifs
- D) C'est une question piège, les listes noires sont toujours sûres

**Q61.** En Flask Python, comment utiliser `Bleach` pour nettoyer du HTML utilisateur ?

```python
import bleach
clean_html = bleach.clean(user_input, tags=['b', 'i'], strip=True)
```
- A) Cette approche est dangereuse, bleach n'existe pas
- B) Le paramètre `strip=True` supprime les balises non autorisées tout en conservant le texte
- C) Cela accepte tous les tags HTML
- D) Bleach ne fonctionne qu'en production

---

### SECTION 12 : Sécurité des APIs et authentification (4 questions)

**Q62.** Quel mécanisme d'authentification est recommandé pour sécuriser une API REST publique ?
- A) Envoyer le mot de passe en paramètre GET à chaque requête
- B) **API Keys** ou **Bearer tokens** (JWT) avec HTTPS obligatoire
- C) Utiliser des cookies sans HttpOnly
- D) Pas d'authentification nécessaire pour une API publique

**Q63.** Qu'est-ce qu'un **JWT (JSON Web Token)** ?
- A) Un fichier de configuration JSON
- B) Un token signé cryptographiquement contenant des claims (revendications) sur l'utilisateur
- C) Un type de base de données
- D) Un protocole réseau

**Q64.** Quel est le risque si un **JWT** est stocké en localStorage (côté navigateur) ?
- A) Aucun risque, localStorage est sécurisé
- B) Les attaques XSS peuvent le voler ; il est mieux de le stocker dans un cookie HttpOnly
- C) LocalStorage est plus rapide que les cookies
- D) C'est la seule façon de stocker un JWT

**Q65.** Quel header HTTP permet une API de déclarer les origines autorisées à faire des requêtes cross-origin ?
- A) `Authorization`
- B) `Access-Control-Allow-Origin`
- C) `X-API-Key`
- D) `User-Agent`

---

### SECTION 13 : Cryptographie et chiffrement (4 questions)

**Q66.** Quelle est la différence entre le chiffrement **symétrique** et **asymétrique** ?
- A) Ils sont identiques
- B) **Symétrique** utilise une clé unique partagée ; **Asymétrique** utilise une paire (clé publique/privée)
- C) Asymétrique est plus rapide que le symétrique
- D) Seul le chiffrement symétrique est sécurisé

**Q67.** Quel est le principal avantage d'utiliser **TLS/SSL** pour les communications réseau ?
- A) Cela rend le serveur plus rapide
- B) Cela chiffre les données en transit et authentifie le serveur via un certificat
- C) Cela supprime le besoin d'authentifier les utilisateurs
- D) TLS/SSL ne fonctionne que pour les petits fichiers

**Q68.** Quel algorithme de chiffrement est considéré comme **compromis** (cassable) aujourd'hui ?
- A) AES-256
- B) TLS 1.3
- C) **MD5** (non : c'est un hash, pas un chiffrement)
- D) RSA-2048

**Q69.** Pourquoi ne pas utiliser des algorithmes de hash (MD5, SHA-1) pour chiffrer les données sensibles ?
- A) Les hashs ne sont pas réversibles par design ; ils ne permettent pas de récupérer les données originales
- B) Les hashs sont trop lents
- C) Les hashs consomment trop de mémoire
- D) Les hashs ne fonctionnent qu'en Python

---

### SECTION 14 : Gestion des erreurs et logging sécurisé (4 questions)

**Q70.** Quel est le danger de révéler des messages d'erreur techniques détaillés aux utilisateurs ?
- A) Les messages d'erreur ralentissent le serveur
- B) Les attaquants peuvent exploiter les informations sur la technologie utilisée (stack trace, versions)
- C) Les messages d'erreur consomment trop de bande passante
- D) Il n'y a aucun risque à révéler des erreurs techniques

**Q71.** En production, comment gérer les erreurs sans révéler d'informations sensibles ?
- A) Afficher le stack trace complet
- B) Afficher un message générique à l'utilisateur et logger les détails côté serveur en secret
- C) Ne pas logger les erreurs
- D) Envoyer l'erreur complète par email à l'utilisateur

**Q72.** Qu'est-ce qu'un **log poisoning** ?
- A) Un programme qui supprime les logs
- B) Un attaquant injecte du contenu malveillant dans les logs pour les corrompre ou tromper les administrateurs
- C) Les logs deviennent automatiquement corruptibles
- D) C'est un type de virus antivirus

**Q73.** Quel type d'information ne devrait JAMAIS être loggée en clair ?
- A) Les noms d'utilisateurs
- B) Les adresses IP
- C) **Les mots de passe, tokens d'authentification ou données de paiement sensibles**
- D) Les heures de connexion

---

### SECTION 15 : Contrôle d'accès et autorisation (4 questions)

**Q74.** Qu'est-ce que **RBAC** (Role-Based Access Control) ?
- A) Une méthode pour chiffrer les données
- B) Contrôler l'accès basé sur les **rôles** assignés aux utilisateurs (admin, user, etc.)
- C) Une forme de chiffrement des mots de passe
- D) Un protocole de communication réseau

**Q75.** Quel est le problème de contrôler l'accès UNIQUEMENT côté client (JavaScript) ?
- A) C'est toujours sûr
- B) Les attaquants peuvent contourner les vérifications côté client ; il FAUT vérifier côté serveur aussi
- C) C'est plus rapide que le contrôle serveur
- D) Les navigateurs bloquent le code JavaScript malveillant automatiquement

---

> **Corrigé réservé à l'enseignant**  
> Le corrigé et le barème sont disponibles dans `docs/quiz1c_corrige.md` (document enseignant, à distribuer via la plateforme institutionnelle uniquement).
