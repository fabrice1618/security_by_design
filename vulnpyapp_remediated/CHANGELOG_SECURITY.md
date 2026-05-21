# Changelog de remédiation - VulnPyApp v2.0 (remediated)

Toutes les vulnérabilités intentionnelles de la v1.0 ont été corrigées
en appliquant les principes Security By Design.

## Corrections appliquées

| # | Vulnérabilité (v1.0) | Correctif (v2.0) | CWE |
|---|----------------------|-------------------|-----|
| 1 | SQLi login | Requêtes paramétrées + ORM SQLAlchemy | CWE-89 |
| 2 | SQLi search | Filtre ORM `ilike` paramétré | CWE-89 |
| 3 | XSS Reflected | Échappement Jinja2 auto + suppression du filtre safe | CWE-79 |
| 4 | XSS Stored | Sanitization Bleach + échappement | CWE-79 |
| 5 | XSS DOM | `textContent` au lieu de `innerHTML` | CWE-79 |
| 6 | CSRF | Flask-WTF CSRFProtect (token global) | CWE-352 |
| 7 | IDOR | Filtrage par `current_user.id` + 403 | CWE-639 |
| 8 | Mass Assignment | Schémas Marshmallow allowlist + rejet des champs inconnus | CWE-915 |
| 9 | SSTI | Suppression du `Template()` dynamique | CWE-1336 |
| 10 | Path Traversal | `werkzeug.secure_filename` + `os.path.realpath` | CWE-22 |
| 11 | Command Injection | `subprocess.run([...], shell=False)` + validation | CWE-78 |
| 12 | MD5 | bcrypt (cost 12) | CWE-327 |
| 13 | Cookies | `HttpOnly`, `SameSite=Strict`, `Secure` en production HTTPS | CWE-614 |
| 14 | Rate limiting | Flask-Limiter sur `/login` (5/min) | CWE-307 |
| 15 | Headers | CSP, HSTS, X-Frame-Options, etc. | CWE-693 |
| - | Debug endpoint | Supprimé | CWE-489 |
| - | Logging | Logs structurés JSON + événements auth | CWE-778 |
| - | Erreurs | Pages d'erreur génériques | CWE-209 |

## Principes Security By Design appliqués

- ✅ **Defense in Depth** : validation + sanitization + échappement
- ✅ **Least Privilege** : utilisateur Docker non-root, rôles vérifiés
- ✅ **Fail Securely** : try/except + redirection vers pages d'erreur
- ✅ **Secure Defaults** : config par défaut sécurisée
- ✅ **Input Validation** : schémas Marshmallow allowlist avec rejet des champs inconnus
- ✅ **Output Encoding** : Jinja2 autoescape activé partout
- ✅ **Separation of Concerns** : security.py, schemas.py isolés
