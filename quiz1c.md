# Quiz 1.C — Fondamentaux de la sécurité web

**Durée : 15 min — Pondération : 10% de la note finale**  
**Format :** QCM, une seule bonne réponse par question

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

> **Corrigé réservé à l'enseignant**  
> Le corrigé et le barème sont disponibles dans `docs/quiz1c_corrige.md` (document enseignant, à distribuer via la plateforme institutionnelle uniquement).
