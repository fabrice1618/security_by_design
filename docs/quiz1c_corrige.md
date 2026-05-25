⚠️ **DOCUMENT ENSEIGNANT — NE PAS DISTRIBUER AUX ÉTUDIANTS**

Ce fichier contient le corrigé détaillé et le barème du Quiz 1.C (36 questions, 25 min). À réserver à la plateforme pédagogique institutionnelle.

---

# Quiz 1.C — Corrigé détaillé et Barème

## 📋 Réponses correctes (Vue d'ensemble)

```
SECTION 1 — Triade CIA
Q1 : B    Q2 : C    Q3 : C    Q4 : B    Q5 : A

SECTION 2 — Injections SQL
Q6 : B    Q7 : C    Q8 : B

SECTION 3 — Cross-Site Scripting (XSS)
Q9 : B    Q10 : C   Q11 : B   Q12 : B

SECTION 4 — RGPD et données personnelles
Q13 : C   Q14 : B   Q15 : C   Q16 : B

SECTION 5 — Protections navigateur
Q17 : C   Q18 : C   Q19 : B   Q20 : A

SECTION 6 — Concepts clés et Principes Security by Design
Q21 : B   Q22 : B   Q23 : B

SECTION 7 — Injections avancées (Path Traversal, Command, SSTI)
Q24 : C   Q25 : B   Q26 : B   Q27 : B

SECTION 8 — Vulnerabilités d'accès et CSRF
Q28 : B   Q29 : B   Q30 : B

SECTION 9 — Authentification sécurisée et Mass Assignment
Q31 : B   Q32 : C   Q33 : A   Q34 : C

SECTION 10 — Protections applicatives (Rate Limiting, SAST/DAST)
Q35 : B   Q36 : A
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

---

### SECTION 2 : Injections SQL

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q6** | **B** | Injection SQL = **exécution de code SQL arbitraire**, permettant accès et modification des données en BDD. C'est le risque principal. | seance1.md : 1.4.1 |
| **Q7** | **C** | Meilleure méthode = **requêtes paramétrées / prepared statements** (ORM SQLAlchemy ou `?` placeholders). Cela sépare code et données. | seance1.md : 1.4.5 |
| **Q8** | **B** | `--` est le commentaire SQL standard (commentaire jusqu'à fin de ligne). Il transforme `WHERE ... AND password='...'` en commentaire ignoré. | seance1.md : 1.4.3 (Exploitation pratique) |

---

### SECTION 3 : Cross-Site Scripting (XSS)

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q9** | **B** | **Reflected XSS** = payload dans l'URL, immédiatement reflété dans la réponse HTTP (non stocké). Non-persistant. | seance1.md : 1.5.1 (Reflected XSS) |
| **Q10** | **C** | `HttpOnly` empêche JavaScript d'accéder au cookie via `document.cookie`. C'est essentiel pour les cookies de session. | seance1.md : 1.1.1 (Authentification forte : cookies `HttpOnly`) |
| **Q11** | **B** | Échappement HTML : `<` → `&lt;` ; `>` → `&gt;`. Les alternatives `\<`, `%3C`, `[LT]` sont incorrectes. | seance1.md : 1.5.3 (Échappement contextuel) |
| **Q12** | **B** | **Sanitization** (via Bleach) supprime les attributs dangereux (`onerror`, `onload`, `onclick`). Validation d'entrée seule est insuffisante. | seance1.md : 1.5.3 (Sanitization avec bleach) |

---

### SECTION 4 : RGPD et données personnelles

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q13** | **C** | Principe de **Minimisation** (Article 5) = collecter le **strict nécessaire** seulement. Réduit la surface de données volées. | seance1.md : 1.2.1 (Minimisation) |
| **Q14** | **B** | Délai de notification CNIL = **72 heures** après découverte d'une fuite de données personnelles présentant un risque. | seance1.md : 1.2.1 (Violation de données) & seance2.md : 2.10 |
| **Q15** | **C** | Recommandé pour mots de passe : **bcrypt / Argon2**. Algorithmes lents, résistant aux attaques GPU/ASIC. MD5 et SHA-256 sont trop rapides (OWASP/NIST). | seance2.md : 2.5 (Stockage des mots de passe) |
| **Q16** | **B** | **Privacy by Design** = intégrer la protection des données dès la **conception**, pas en ajout tardif (Article 25 RGPD). | seance1.md : 1.2.1 (Privacy by Design) |

---

### SECTION 5 : Protections navigateur

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q17** | **C** | **Same-Origin Policy (SOP)** = mécanisme du navigateur empêchant scripts d'une origine d'accéder aux données d'une autre origine. Isolation automatique. | seance1.md : 1.6.1 (Same-Origin Policy) |
| **Q18** | **C** | `SameSite=Strict` offre la **meilleure protection CSRF**, mais peut bloquer certains parcours légitimes depuis liens entrants. | seance2.md : 2.1.3 (Détail des modes SameSite) |
| **Q19** | **B** | `Access-Control-Allow-Origin: *` + `Access-Control-Allow-Credentials: true` = **violation directe** de la spécification CORS. Navigateur doit rejeter. | seance1.md : 1.6.2 (Configuration dangereuse) |
| **Q20** | **A** | **Content-Security-Policy (CSP)** = whitelist de sources autorisées pour ressources. Peut bloquer scripts d'origines non autorisées. | seance1.md : 1.6.3 (Content Security Policy) |

---

### SECTION 6 : Concepts clés et Principes Security by Design

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q21** | **B** | **CVSS v3.1** = standard pour évaluer et noter la gravité des vulnérabilités sur une échelle de 0 à 10. Scores : Faible (0.1–3.9), Moyen (4–6.9), Élevé (7–8.9), Critique (9–10). | seance1.md : 1.1.4 (CVSS Scoring System) |
| **Q22** | **B** | **Least Privilege** (Moindre Privilège) = accorder **uniquement les droits strictement nécessaires**. L'un des 6 principes Security by Design. | seance1.md : 1.1.3 (Principes Security by Design) |
| **Q23** | **B** | **Surface d'attaque** = ensemble des **points d'entrée** susceptibles d'être exploités : formulaires, URLs, headers HTTP, APIs, dépendances, infrastructure. | seance1.md : 1.1.2 (Surface d'attaque) |

---

### SECTION 7 : Injections avancées

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q24** | **C** | **Path Traversal** (Traversée de répertoire) = utiliser `../` pour remonter la hiérarchie et accéder à fichiers en dehors du répertoire autorisé. Exemple : `/download?file=../../etc/passwd`. | seance1.md : 1.7.1 (Path Traversal) |
| **Q25** | **B** | `shell=True` + f-string = l'utilisateur peut injecter des commandes via les séparateurs `;`, `\|`, `&&`, etc. `ping localhost; cat /etc/passwd` exécute deux commandes. | seance1.md : 1.7.2 (Exemple vulnérable) |
| **Q26** | **B** | **SSTI** (Server-Side Template Injection) = injection de code dans un template côté serveur (Jinja2, etc.), permettant l'**exécution de code arbitraire (RCE)** complet. | seance2.md : 2.4.1 & 2.4.2 (Exploitation — Du RCE complet) |
| **Q27** | **B** | Prévention de Command Injection : utiliser `subprocess.run(['ping', '-c', '1', host], shell=False)`. Liste d'arguments + `shell=False` = pas d'interprétation shell. | seance1.md : 1.7.2 (Défense — pourquoi shell=False protège) |

---

### SECTION 8 : Vulnerabilités d'accès et CSRF

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q28** | **B** | **Authentification** (AuthN) = vérifier l'**identité** (qui êtes-vous ?) ; **Autorisation** (AuthZ) = vérifier les **droits** (que pouvez-vous faire ?). Concepts **indépendants** et **complémentaires**. | seance2.md : 2.2.0 (Authentification vs Autorisation) |
| **Q29** | **B** | **IDOR** (Insecure Direct Object Reference) = accès **non autorisé** à des ressources via une **référence prédictible** (ID séquentiel) **sans vérifier la propriété**. Exemple : `/api/orders/5` accessible par tout utilisateur. | seance2.md : 2.2.1–2.2.2 (IDOR) |
| **Q30** | **B** | **CSRF** (Cross-Site Request Forgery) = le **navigateur envoie automatiquement les cookies de session**, même pour requêtes initiées depuis un **autre site**. L'attaquant ne connaît jamais le cookie, c'est le navigateur qui le fournit. | seance2.md : 2.1.1 (Pourquoi CSRF est-il possible) |

---

### SECTION 9 : Authentification sécurisée et Mass Assignment

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q31** | **B** | **Mass Assignment** = l'application accepte **tous les champs POST/JSON sans filtrage**, permettant à l'attaquant d'injecter des champs sensibles comme `is_admin=true`. | seance2.md : 2.3.1 (Mass Assignment) |
| **Q32** | **C** | Recommandé pour hasher mots de passe : **bcrypt ou Argon2**. Coût configurable, résistant GPU/ASIC. **MD5 et SHA-256 sont trop rapides** → brute force trivial. **Base64 n'est pas du hashage** (décodable). | seance2.md : 2.5 (Hiérarchie de mauvaises à bonnes pratiques) |
| **Q33** | **A** | **Session Fixation** = attaquant fixe un identifiant de session et la victime l'utilise (puis se connecte, le fixant). Prévention = **régénérer complètement la session après login**. | seance2.md : 2.6.2 (SessionManager.login_user) |
| **Q34** | **C** | `SameSite=Strict` offre la **meilleure protection CSRF** (cookie jamais envoyé en cross-site), mais peut casser les liens entrants. `Lax` = bon compromis par défaut. | seance2.md : 2.1.3 (Détail des modes SameSite) |

---

### SECTION 10 : Protections applicatives

| Q | Réponse | Justification | Référence |
|----|---------|---------------|-----------|
| **Q35** | **B** | **Rate limiting** = limiter le nombre de requêtes par minute/heure sur un endpoint. Sur `/login` : 5 tentatives/min. Bloque le brute force, l'énumération. | seance2.md : 2.7 (Flask-Limiter) |
| **Q36** | **A** | **SAST** (Static Analysis) = analyse le **code source statiquement** (Bandit, Semgrep). **DAST** (Dynamic Analysis) = teste l'**application en cours d'exécution** (ZAP, Burp). **Tous deux nécessaires**. | seance2.md : 2.8 (Outils Python pour le SDLC sécurisé) |

---

## 📊 BARÈME DE NOTATION

### Par réponse

- **Réponse correcte** : 1 point
- **Réponse incorrecte** : 0 point
- **Pas de réponse** : 0 point

**Total** : 36 points

### Conversion sur 20

```
Formule de conversion : (Points obtenus / 36) × 20

Exemples :
- 36/36 = 20/20 (100%)
- 32/36 = 17.8/20 (≈89%)
- 30/36 = 16.7/20 (≈83%)
- 25/36 = 13.9/20 (≈69%)
- 18/36 = 10/20 (50% — seuil critique)
- 12/36 = 6.7/20 (≈33% — insuffisant)
```

### Grille de notation alternative (sur 10)

```
Conversion sur 10 : (Points obtenus / 36) × 10

- 32–36 : 8.9–10/10 (Excellent)
- 27–31 : 7.5–8.6/10 (Bon)
- 21–26 : 5.8–7.2/10 (Acceptable)
- 18–20 : 5/10 (Limite)
- <18 : <5/10 (Insuffisant)
```

---

## 📈 DISTRIBUTION PAR THÈME

| Thème | Questions | # Q | Poids % | Taux réussite attendu |
|-------|-----------|-----|---------|----------------------|
| **Triade CIA** | Q1–Q5 | 5 | 13.9% | ≥90% (fondamentaux) |
| **Injections SQL** | Q6–Q8 | 3 | 8.3% | ≥85% |
| **XSS** | Q9–Q12 | 4 | 11.1% | ≥80% |
| **RGPD** | Q13–Q16 | 4 | 11.1% | ≥75% (aspect légal) |
| **Protections nav** | Q17–Q20 | 4 | 11.1% | ≥70% |
| **Concepts & Principes** | Q21–Q23 | 3 | 8.3% | 60–75% (intermédiaire) |
| **Injections avancées** | Q24–Q27 | 4 | 11.1% | 55–70% |
| **Accès & CSRF** | Q28–Q30 | 3 | 8.3% | 50–70% |
| **Auth & Mass Assignment** | Q31–Q34 | 4 | 11.1% | 50–65% |
| **Protections appli** | Q35–Q36 | 2 | 5.6% | 60–75% |
| **TOTAL** | — | **36** | **100%** | — |

---

## 📋 INTERPRÉTATION PAR PERFORMANCE

| Plage de points | Plage % | Interprétation | Recommandation |
|---|---|---|---|
| **30–36** | **83–100%** | ✅ **Excellent** — Maîtrise complète | Étudiant prêt pour examen/pratique avancée |
| **26–29** | **72–82%** | ✅ **Très bon** — Bonne compréhension | Quelques lacunes mineures à revoir |
| **21–25** | **58–71%** | ⚠️ **Bon** — Acquis solides | Réviser certains modules (voir analyse par section) |
| **18–20** | **50–57%** | ⚠️ **Juste suffisant** — Seuil critique | **Demander une révision guidée avant examen** |
| **12–17** | **33–49%** | ❌ **Insuffisant** — Gaps importants | **Revoir l'ensemble du cours + rattrapage obligatoire** |
| **<12** | **<33%** | ❌ **Très insuffisant** — Compréhension minimale | **Entretien avec l'enseignant + soutien intensif** |

---

## 🔍 ANALYSE PAR SECTION (pour feedback étudiant)

### Si taux de réussite < attendu :

**Sections 1–5 (Fondamentaux)** — Taux attendu ≥75%
- Si <70% : réviser seance1.md modules 1.1 (CIA) et 1.4–1.6 (Injections, XSS, protections)
- Points de focus : concepts de base CIA, requêtes paramétrées, échappement

**Sections 6–7 (Intermédiaire)** — Taux attendu 60–75%
- Si <55% : revoir seance1.md modules 1.1.3 (Principes), 1.7 (Path Traversal, Command) + seance2.md module 2.4 (SSTI)
- Points de focus : principes Security by Design, injections système, templates

**Sections 8–10 (Avancé)** — Taux attendu 55–75%
- Si <50% : revoir seance2.md modules 2.1–2.3 (CSRF, IDOR, Mass Assignment) + 2.5–2.7 (Auth, Sessions, Rate Limiting)
- Points de focus : autorisation, sécurité de session, mitigations avancées

---

## 📝 REMARQUES PÉDAGOGIQUES

### Notes générales

- **Temps moyen par question** : 25 min / 36 Q ≈ **42 secondes/Q** (raisonnable pour 4 choix)
- **Distribution équilibrée** : chaque thème représente 5–13% de la notation
- **Progression pédagogique** : Sections 1–5 (basiques) → Sections 6–10 (appliquées/avancées)

### Premiers signes d'alerte

| Indicateur | Action |
|-----------|--------|
| >30% échouent Q21–Q23 (Principes) | Ajouter une séance de review des 6 principes Security by Design |
| >40% échouent Q24–Q27 (Injections avancées) | Proposer lab pratique sur Path Traversal & Command Injection |
| >50% échouent Q28–Q30 (Accès) | Revoir CSRF vs IDOR ; session de clarification nécessaire |
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


