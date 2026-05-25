# Quiz 1.C — Fondamentaux de la sécurité web

**Durée : 25 min — Pondération : 10% de la note finale**  
**Format :** QCM, une seule bonne réponse par question  
**Remarque :** Ce quiz (36 questions) couvre l'intégrité des 3 séances, améliorant la couverture pédagogique : principes Security by Design, injections avancées (Path Traversal, Command Injection, SSTI), CSRF, IDOR, authentification sécurisée, sessions, rate limiting, et processus SDLC (SAST/DAST).

---

## 📝 Questions

### SECTION 1 : Triade CIA (5 questions)

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

---

### SECTION 2 : Injections SQL (3 questions)

**Q6.** Quel est le **principal risque** d'une injection SQL ?
- A) Ralentissement des serveurs
- B) Exécution de code SQL arbitraire et accès/modification des données
- C) Saturation de la bande passante
- D) Perte de fichiers sur le disque dur

**Q7.** Quelle est la meilleure méthode pour prévenir une injection SQL en Python ?
- A) Valider les entrées avec regex
- B) Mettre en minuscule l'entrée utilisateur
- C) Utiliser des requêtes paramétrées / prepared statements
- D) Limiter la longueur des chaînes à 10 caractères

**Q8.** Quel est le commentaire SQL qui permet de contourner la vérification du mot de passe ?

```sql
SELECT * FROM users WHERE email='admin@test.com' _______ AND password='...'
```
- A) `/**/`
- B) `--`
- C) `#`
- D) `//`

---

### SECTION 3 : Cross-Site Scripting (XSS) (4 questions)

**Q9.** Quel type de XSS est reflété immédiatement dans la réponse HTTP sans être stocké ?
- A) Stored XSS
- B) Reflected XSS
- C) DOM-based XSS
- D) Blind XSS

**Q10.** Quel flag du cookie de session empêche l'accès via JavaScript ?
- A) `Secure`
- B) `SameSite`
- C) `HttpOnly`
- D) `Domain`

**Q11.** Quel échappement est approprié pour afficher du texte dans une balise HTML ?
- A) `<` → `\<`
- B) `<` → `&lt;`
- C) `<` → `%3C`
- D) `<` → `[LT]`

**Q12.** Un payload XSS `<img src=x onerror=alert(1)>` peut être bloqué par :
- A) Validation d'entrée uniquement
- B) Sanitization (suppression des attributs `onerror`)
- C) Rate limiting
- D) Authentification forte

---

### SECTION 4 : RGPD et données personnelles (4 questions)

**Q13.** Quel est le principe RGPD fondamental qui impose de collecter le **minimum** de données ?
- A) Licéité
- B) Limitation de la conservation
- C) Minimisation
- D) Intégrité

**Q14.** Après une fuite de données personnelles, quel est le délai de notification à la CNIL ?
- A) 24 heures
- B) 72 heures
- C) 7 jours
- D) 30 jours

**Q15.** Quel algorithme de hashage est recommandé pour stocker les mots de passe ?
- A) MD5
- B) SHA-256
- C) bcrypt / Argon2
- D) Base64

**Q16.** « Privacy by Design » signifie :
- A) Ajouter des mesures de confidentialité après le déploiement
- B) Intégrer la protection des données dès la conception
- C) Ignorer le RGPD pendant le développement
- D) Chiffrer uniquement les données sensibles

---

### SECTION 5 : Protections navigateur (4 questions)

**Q17.** Quel mécanisme empêche les scripts d'une autre origine d'accéder aux données ?
- A) CORS (en tant que header de réponse)
- B) `Content-Security-Policy`
- C) La **Same-Origin Policy** du navigateur
- D) `X-Frame-Options`

**Q18.** Quel mode de **SameSite cookie** offre la meilleure protection CSRF mais peut bloquer les liens entrants ?
- A) `None`
- B) `Lax`
- C) `Strict`
- D) `Unsecured`

**Q19.** Quel est le problème de `Access-Control-Allow-Origin: *` combiné à `credentials: true` ?
- A) Aucun problème
- B) Violation directe de la spécification CORS
- C) Ralentit les requêtes
- D) Augmente la consommation mémoire

**Q20.** La **Content-Security-Policy (CSP)** peut bloquer :
- A) Scripts d'origines non autorisées
- B) Uniquement les requêtes HTTPS
- C) Les fichiers trop volumineux
- D) Les connexions VPN

---

### SECTION 6 : Concepts clés et Principes Security by Design (3 questions)

**Q21.** Lequel de ces énoncés décrit correctement le **CVSS v3.1** ?
- A) Un type de vulnérabilité critique de réseau
- B) Un standard pour évaluer et noter la gravité des vulnérabilités (score 0–10)
- C) Un algorithme de chiffrement asymétrique
- D) Une politique d'authentification multi-facteur

**Q22.** Le principe Security by Design « **Least Privilege** » signifie :
- A) Donner l'accès administrateur à tous les utilisateurs
- B) Accorder uniquement les droits strictement nécessaires à un utilisateur
- C) Minimiser les logs de sécurité
- D) Utiliser les mots de passe les plus simples possible

**Q23.** Qu'est-ce qu'une **surface d'attaque** en sécurité informatique ?
- A) La zone physique du serveur
- B) L'ensemble des points d'entrée (formulaires, APIs, ports) susceptibles d'être exploités
- C) Le nombre total d'utilisateurs connectés
- D) La vitesse des connexions réseau

---

### SECTION 7 : Injections avancées (Path Traversal, Command Injection, SSTI) (4 questions)

**Q24.** Quelle vulnérabilité permet de traverser la hiérarchie des répertoires en utilisant `../` pour accéder à des fichiers sensibles ?
- A) Injection SQL
- B) Cross-Site Scripting
- C) **Path Traversal** (Traversée de répertoire)
- D) Command Injection

**Q25.** Pourquoi utiliser `shell=True` dans `subprocess.check_output(f"ping {host}", shell=True)` en Python est-il dangereux ?
- A) Cela ralentit les performances
- B) L'utilisateur peut injecter des commandes via des séparateurs comme `;` ou `|`
- C) Cela fonctionne uniquement sous Linux
- D) Cela consomme trop de mémoire

**Q26.** Qu'est-ce qu'une vulnérabilité **SSTI** (Server-Side Template Injection) ?
- A) Injection de balises HTML côté client (navigateur)
- B) Injection de code dans un template côté serveur, permettant l'exécution de code arbitraire (RCE)
- C) Injection de SQL dans une base de données
- D) Injection de JavaScript que le serveur réfléchit

**Q27.** Quel fonction Python peut aider à prévenir les injections de commandes ?
- A) Utiliser `os.system()` avec validation simples
- B) Utiliser `subprocess.run()` avec une liste d'arguments et `shell=False`
- C) Déactiver le shell de l'OS
- D) Aucune, les injections de commandes sont inévitables

---

### SECTION 8 : Vulnerabilités d'accès et CSRF (4 questions)

**Q28.** Quelle est la différence fondamentale entre **Authentification** et **Autorisation** ?
- A) Ce sont deux termes synonymes
- B) **Authentification** = vérifier l'identité (qui êtes-vous ?) ; **Autorisation** = vérifier les droits (que pouvez-vous faire ?)
- C) Authentification s'applique uniquement aux administrateurs
- D) Autorisation est vérifiée avant l'authentification

**Q29.** Qu'est-ce qu'une vulnérabilité **IDOR** (Insecure Direct Object Reference) ?
- A) Une injection de commande système
- B) Accès non autorisé à des ressources via une référence directe prédictible sans vérifier la propriété
- C) Une authentification sans mot de passe
- D) Une fuite de session cookie via le réseau

**Q30.** **CSRF** (Cross-Site Request Forgery) exploite le fait que :
- A) Les mots de passe sont stockés en clair
- B) Le navigateur envoie automatiquement les cookies de session, même pour des requêtes initiées depuis un autre site
- C) Les bases de données ne sont pas chiffrées
- D) Les utilisateurs ne lisent pas les conditions d'utilisation

---

### SECTION 9 : Authentification sécurisée et Mass Assignment (4 questions)

**Q31.** **Mass Assignment** se produit quand :
- A) Plusieurs utilisateurs se connectent simultanément
- B) L'application accepte tous les champs POST sans filtrage, permettant la modification de champs sensibles comme `is_admin`
- C) Le serveur refuse trop de connexions
- D) Le cache est saturé

**Q32.** Entre **MD5**, **SHA-256** et **bcrypt**, lequel est recommandé pour hasher les mots de passe en 2026 ?
- A) MD5 (résistant et rapide)
- B) SHA-256 (standard moderne)
- C) **bcrypt** ou **Argon2** (coût configurable, résistant aux attaques GPU/ASIC)
- D) Base64 (facile à implémenter)

**Q33.** Qu'est-ce qu'une **Session Fixation** et comment la prévenir ?
- A) L'attaquant fixe un identifiant de session et la victime l'utilise ; prévention : régénérer complètement la session après login
- B) C'est impossible à prévenir
- C) À résoudre uniquement avec HTTPS
- D) À traiter avec des cookies sans attribut Secure

**Q34.** Quel mode **SameSite** du cookie de session offre la meilleure protection **CSRF** mais peut bloquer certains accès légitimes ?
- A) `None`
- B) `Lax`
- C) **`Strict`**
- D) `Encrypted`

---

### SECTION 10 : Protections applicatives (Rate Limiting, SAST/DAST) (2 questions)

**Q35.** **Rate limiting** sur un endpoint sensible comme `/login` sert à :
- A) Accélérer les connexions réussies
- B) Limiter le nombre de tentatives par minute pour bloquer les attaques par brute force
- C) Chiffrer automatiquement les mots de passe
- D) Ajouter un délai de réseau artificiel

**Q36.** Quelle est la différence entre **SAST** et **DAST** dans un SDLC sécurisé ?
- A) SAST analyse le code source statiquement ; DAST teste l'application en cours d'exécution
- B) Ce sont deux noms du même processus
- C) SAST ne détecte que les erreurs de syntaxe
- D) DAST ne fonctionne qu'en production

---

> **Corrigé réservé à l'enseignant**  
> Le corrigé et le barème sont disponibles dans `docs/quiz1c_corrige.md` (document enseignant, à distribuer via la plateforme institutionnelle uniquement).
