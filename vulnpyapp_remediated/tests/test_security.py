"""
Tests de sécurité - application remédiée v2.0
Tous ces tests doivent passer (✅) sur la v2.0 sécurisée.
"""
import pytest
from models import User
from extensions import db


# ============================================================
# FIX #1 & #2 - SQL Injection
# ============================================================

class TestSQLInjection:

    def test_sqli_login_bypass_blocked(self, client):
        """L'injection SQL dans le login doit être bloquée"""
        r = client.post('/login', data={
            'email': "' OR '1'='1' --",
            'password': 'anything'
        })
        assert r.status_code in (400, 401)
        assert b'Invalid' in r.data or b'invalid' in r.data

    def test_sqli_login_union_blocked(self, client):
        """UNION SELECT dans l'email doit être rejeté"""
        r = client.post('/login', data={
            'email': "' UNION SELECT 1,2,3 --",
            'password': 'x'
        })
        assert r.status_code in (400, 401)

    def test_sqli_search_blocked(self, client):
        """SQL Injection dans la recherche doit être neutralisée"""
        r = client.get("/search?q=' OR '1'='1")
        assert r.status_code == 200
        # Aucun dump de base de données dans la réponse
        assert b'sqlite' not in r.data.lower()
        assert b'syntax error' not in r.data.lower()

    def test_sqli_search_tautology_blocked(self, client):
        """Pas de fuite de données via tautologie"""
        r = client.get("/search?q=x' OR 1=1--")
        assert r.status_code == 200
        # Ne doit pas retourner TOUS les produits
        assert r.data.count(b'<li>') <= 2


# ============================================================
# FIX #3 #4 #5 - XSS
# ============================================================

class TestXSS:

    def test_xss_reflected_escaped(self, client):
        """XSS reflété doit être échappé"""
        payload = '<script>alert(1)</script>'
        r = client.get(f'/search?q={payload}')
        assert b'<script>alert(1)</script>' not in r.data
        assert b'&lt;script&gt;' in r.data or b'alert' not in r.data

    def test_xss_stored_bleach_sanitized(self, auth_client):
        """XSS stocké doit être nettoyé par Bleach"""
        payload = '<img src=x onerror=alert(1)>'
        auth_client.post('/comments', data={'content': payload})
        r = auth_client.get('/comments')
        assert b'onerror' not in r.data
        assert b'alert(1)' not in r.data

    def test_xss_stored_script_tag_removed(self, auth_client):
        """Balise script dans commentaire doit être supprimée"""
        payload = '<script>document.cookie</script>Innocent text'
        auth_client.post('/comments', data={'content': payload})
        r = auth_client.get('/comments')
        assert b'<script>' not in r.data
        # Le texte innocent reste
        assert b'Innocent text' in r.data

    def test_xss_allowed_tags_preserved(self, auth_client):
        """Tags HTML autorisés doivent être conservés"""
        auth_client.post('/comments', data={
            'content': '<b>Bold</b> and <em>italic</em>'
        })
        r = auth_client.get('/comments')
        assert b'<b>Bold</b>' in r.data
        assert b'<em>italic</em>' in r.data

    def test_hello_no_ssti(self, client):
        """SSTI via paramètre name doit être bloquée"""
        r = client.get('/hello?name={{ 7*7 }}')
        assert b'49' not in r.data
        # L'expression peut etre affichee litteralement, mais jamais evaluee.
        assert b'{{ 7*7 }}' in r.data

    def test_hello_xss_escaped(self, client):
        """XSS dans /hello doit être échappé"""
        r = client.get('/hello?name=<script>alert(1)</script>')
        assert b'<script>' not in r.data


# ============================================================
# FIX #6 - CSRF
# ============================================================

class TestCSRF:

    def test_csrf_token_present_in_login(self, client):
        """Le formulaire login doit contenir un token CSRF"""
        r = client.get('/login')
        assert b'csrf_token' in r.data

    def test_csrf_token_present_in_register(self, client):
        """Le formulaire register doit contenir un token CSRF"""
        r = client.get('/register')
        assert b'csrf_token' in r.data

    def test_profile_update_without_csrf_rejected(self, app, auth_client):
        """Mise à jour de profil sans token CSRF doit être rejetée"""
        # Les autres tests desactivent CSRF pour eviter d'alourdir chaque POST.
        # Ici on le reactive explicitement pour verifier le controle reel.
        app.config['WTF_CSRF_ENABLED'] = True
        r = auth_client.post('/profile/update', data={
            'username': 'alice2',
            'bio': 'updated without token'
        })
        assert r.status_code == 400


# ============================================================
# FIX #7 - IDOR
# ============================================================

class TestIDOR:

    def test_idor_cannot_access_other_user_order(self, auth_client, app):
        """Alice ne peut pas accéder à la commande de Bob"""
        with app.app_context():
            from models import Order
            bob = User.query.filter_by(username='bob').first()
            bob_order = Order.query.filter_by(user_id=bob.id).first()

        if bob_order:
            r = auth_client.get(f'/api/orders/{bob_order.id}')
            assert r.status_code == 404, \
                f"Expected 404, got {r.status_code} - IDOR vulnerability present"

    def test_idor_can_access_own_order(self, auth_client, app):
        """Alice peut accéder à ses propres commandes"""
        with app.app_context():
            from models import Order
            alice = User.query.filter_by(username='alice').first()
            alice_order = Order.query.filter_by(user_id=alice.id).first()

        if alice_order:
            r = auth_client.get(f'/api/orders/{alice_order.id}')
            assert r.status_code == 200

    def test_idor_admin_can_access_all_orders(self, admin_client, app):
        """Admin peut accéder à toutes les commandes"""
        with app.app_context():
            from models import Order
            bob = User.query.filter_by(username='bob').first()
            bob_order = Order.query.filter_by(user_id=bob.id).first()

        if bob_order:
            r = admin_client.get(f'/api/orders/{bob_order.id}')
            assert r.status_code == 200

    def test_user_api_hides_sensitive_fields(self, auth_client, app):
        """L'API user masque email et is_admin pour les autres utilisateurs"""
        with app.app_context():
            bob = User.query.filter_by(username='bob').first()
            bob_id = bob.id

        r = auth_client.get(f'/api/users/{bob_id}')
        assert r.status_code == 200
        data = r.get_json()
        assert 'email' not in data
        assert 'is_admin' not in data
        assert 'username' in data


# ============================================================
# FIX #8 - Mass Assignment
# ============================================================

class TestMassAssignment:

    def test_is_admin_not_settable_via_register(self, client, app):
        """Le champ is_admin doit être rejeté à l'inscription"""
        r = client.post('/register', data={
            'email': 'hacker@test.local',
            'username': 'hacker',
            'password': 'Hack123!',
            'is_admin': 'true',        # tentative d'injection
            'is_admin[]': 'true',
            'is_admin[0]': '1'
        })
        assert r.status_code == 400

        with app.app_context():
            hacker = User.query.filter_by(email='hacker@test.local').first()
            assert hacker is None

    def test_profile_update_cannot_escalate_privilege(self, auth_client, app):
        """Mise à jour de profil ne peut pas changer is_admin"""
        auth_client.post('/profile/update', data={
            'username': 'alice',
            'bio': 'test',
            'is_admin': 'true'
        })

        with app.app_context():
            alice = User.query.filter_by(username='alice').first()
            assert alice.is_admin is False


# ============================================================
# FIX #9 - SSTI
# ============================================================

class TestSSTI:

    def test_ssti_jinja_expression_not_evaluated(self, app, client):
        """Expression Jinja2 dans l'URL ne doit pas être évaluée"""
        r = client.get('/hello?name={{ config.SECRET_KEY }}')
        assert r.status_code == 200
        assert app.config['SECRET_KEY'].encode() not in r.data
        assert b'{{ config.SECRET_KEY }}' in r.data

    def test_ssti_python_expression_blocked(self, client):
        r = client.get('/hello?name={{ [].__class__.__mro__ }}')
        assert b'__mro__' in r.data
        assert b'<class' not in r.data
        assert b'object' not in r.data


# ============================================================
# FIX #10 - Path Traversal
# ============================================================

class TestPathTraversal:

    def test_path_traversal_dotdot_blocked(self, auth_client):
        """../etc/passwd doit être bloqué"""
        r = auth_client.get('/download?file=../../etc/passwd')
        assert r.status_code in (400, 404)

    def test_path_traversal_encoded_blocked(self, auth_client):
        """Encodages URL du path traversal doivent être bloqués"""
        r = auth_client.get('/download?file=..%2F..%2Fetc%2Fpasswd')
        assert r.status_code in (400, 404)

    def test_path_traversal_disallowed_extension(self, auth_client):
        """Fichiers .py ne doivent pas être téléchargeables"""
        r = auth_client.get('/download?file=app.py')
        assert r.status_code in (400, 404)

    def test_path_traversal_empty_file_blocked(self, auth_client):
        """Paramètre file vide doit être rejeté"""
        r = auth_client.get('/download?file=')
        assert r.status_code in (400, 404)


# ============================================================
# FIX #11 - Command Injection
# ============================================================

class TestCommandInjection:

    def test_command_injection_semicolon_blocked(self, auth_client):
        """Injection avec ; doit être bloquée"""
        r = auth_client.post('/ping', data={'host': 'localhost; cat /etc/passwd'})
        assert r.status_code in (400, 403)
        assert b'root:' not in r.data

    def test_command_injection_pipe_blocked(self, auth_client):
        """Injection avec | doit être bloquée"""
        r = auth_client.post('/ping', data={'host': 'localhost|id'})
        assert r.status_code in (400, 403)

    def test_command_injection_backtick_blocked(self, auth_client):
        """Injection avec backtick doit être bloquée"""
        r = auth_client.post('/ping', data={'host': '`id`'})
        assert r.status_code in (400, 403)

    def test_command_injection_private_ip_blocked(self, auth_client):
        """Ping vers IP privée (SSRF) doit être bloqué"""
        r = auth_client.post('/ping', data={'host': '192.168.1.1'})
        assert r.status_code in (400, 403)

    def test_command_injection_loopback_blocked(self, auth_client):
        """Ping vers loopback doit être bloqué"""
        r = auth_client.post('/ping', data={'host': '127.0.0.1'})
        assert r.status_code in (400, 403)


# ============================================================
# FIX #12 - Hashage
# ============================================================

class TestPasswordHashing:

    def test_bcrypt_used_not_md5(self, app):
        """Le hash stocké doit commencer par $2b$ (bcrypt)"""
        with app.app_context():
            alice = User.query.filter_by(username='alice').first()
            assert alice.password_hash.startswith('$2b$'), \
                f"Expected bcrypt hash, got: {alice.password_hash[:10]}"

    def test_password_not_stored_plaintext(self, app):
        """Le mot de passe ne doit pas être stocké en clair"""
        with app.app_context():
            alice = User.query.filter_by(username='alice').first()
            assert alice.password_hash != 'Alice123!'
            assert len(alice.password_hash) > 30

    def test_bcrypt_cost_factor(self, app):
        """Le cost factor bcrypt doit être >= 12"""
        with app.app_context():
            alice = User.query.filter_by(username='alice').first()
            # Format bcrypt: $2b$COST$...
            parts = alice.password_hash.split('$')
            cost = int(parts[2])
            assert cost >= 12, f"bcrypt cost {cost} is too low (minimum 12)"


# ============================================================
# FIX #13 - Cookies sécurisés
# ============================================================

class TestSecureCookies:

    def test_session_cookie_httponly(self, client):
        """Le cookie de session doit avoir le flag HttpOnly"""
        r = client.post('/login', data={
            'email': 'alice@vulnpyapp.local',
            'password': 'Alice123!'
        })
        set_cookie = '\n'.join(r.headers.getlist('Set-Cookie'))
        assert 'HttpOnly' in set_cookie

    def test_session_cookie_samesite(self, client):
        """Le cookie de session doit avoir SameSite=Strict"""
        r = client.post('/login', data={
            'email': 'alice@vulnpyapp.local',
            'password': 'Alice123!'
        })
        set_cookie = r.headers.get('Set-Cookie', '')
        if set_cookie:
            assert 'SameSite=Strict' in set_cookie or \
                   'samesite=strict' in set_cookie.lower()


# ============================================================
# FIX #14 - Rate Limiting
# ============================================================

class TestRateLimiting:

    def test_login_rate_limited_after_5_attempts(self, client):
        """Le login doit être rate-limité après 5 tentatives"""
        for _ in range(5):
            client.post('/login', data={
                'email': 'notexist@test.local',
                'password': 'WrongPass1!'
            })
        r = client.post('/login', data={
            'email': 'notexist@test.local',
            'password': 'WrongPass1!'
        })
        assert r.status_code == 429, \
            f"Expected 429 Too Many Requests, got {r.status_code}"


# ============================================================
# FIX #15 - Security Headers
# ============================================================

class TestSecurityHeaders:

    def test_x_content_type_options(self, client):
        r = client.get('/')
        assert r.headers.get('X-Content-Type-Options') == 'nosniff'

    def test_x_frame_options(self, client):
        r = client.get('/')
        assert r.headers.get('X-Frame-Options') in ('DENY', 'SAMEORIGIN')

    def test_csp_header_present(self, client):
        r = client.get('/')
        csp = r.headers.get('Content-Security-Policy', '')
        assert "default-src 'self'" in csp or "default-src" in csp

    def test_referrer_policy(self, client):
        r = client.get('/')
        assert r.headers.get('Referrer-Policy') == 'no-referrer'

    def test_no_server_header_leakage(self, client):
        r = client.get('/')
        server = r.headers.get('Server', '')
        assert 'Werkzeug' not in server or server == ''


# ============================================================
# FIX admin_required
# ============================================================

class TestAccessControl:

    def test_admin_route_blocked_for_anonymous(self, client):
        r = client.get('/admin')
        assert r.status_code in (302, 401, 403)

    def test_admin_route_blocked_for_regular_user(self, auth_client):
        r = auth_client.get('/admin')
        assert r.status_code == 403

    def test_admin_route_accessible_for_admin(self, admin_client):
        r = admin_client.get('/admin')
        assert r.status_code == 200

    def test_unauthenticated_cannot_access_profile(self, client):
        r = client.get('/profile')
        assert r.status_code == 302
        assert '/login' in r.headers.get('Location', '')
