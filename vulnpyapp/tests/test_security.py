"""
Tests de sécurité - À faire PASSER après remédiation.
Actuellement, ces tests ÉCHOUENT car l'app est volontairement vulnérable.
"""

def test_sqli_login_blocked(client):
    r = client.post('/login', data={
        'email': "' OR '1'='1' --",
        'password': 'x'
    }, follow_redirects=False)
    assert r.status_code != 302, "SQLi bypass should be blocked"

def test_xss_search_escaped(client):
    r = client.get('/search?q=<script>alert(1)</script>')
    assert b'<script>alert(1)</script>' not in r.data

def test_mass_assignment_blocked(client):
    client.post('/register', data={
        'email': 'attacker@test.com',
        'username': 'attacker',
        'password': 'Pass123!',
        'is_admin': 'true'
    })
    client.post('/login', data={'email': 'attacker@test.com', 'password': 'Pass123!'})
    r = client.get('/admin')
    assert r.status_code == 403, "is_admin should not be settable via form"

def test_secure_cookies(client):
    client.post('/login', data={'email': 'alice@vulnpyapp.local', 'password': 'Alice123!'})
    cookie = client.cookie_jar._cookies
    # Après remédiation : HttpOnly, Secure, SameSite=Strict attendus
    assert True  # placeholder
