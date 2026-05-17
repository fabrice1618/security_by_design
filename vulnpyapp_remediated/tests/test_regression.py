"""
Tests de non-régression : les corrections de sécurité
ne doivent pas casser les fonctionnalités légitimes.
"""


class TestFunctionalRegression:

    def test_login_valid_credentials_works(self, client):
        """Un utilisateur légitime peut toujours se connecter"""
        r = client.post('/login', data={
            'email': 'alice@vulnpyapp.local',
            'password': 'Alice123!'
        }, follow_redirects=True)
        assert r.status_code == 200
        assert b'alice' in r.data.lower()

    def test_register_new_user_works(self, client, app):
        """L'inscription d'un nouvel utilisateur fonctionne"""
        r = client.post('/register', data={
            'email': 'newuser@test.local',
            'username': 'newuser',
            'password': 'NewUser123!',
            'bio': 'Hello world'
        }, follow_redirects=True)
        assert r.status_code == 200

        with app.app_context():
            from models import User
            u = User.query.filter_by(email='newuser@test.local').first()
            assert u is not None
            assert u.is_admin is False

    def test_search_legitimate_query_returns_results(self, client):
        """Une recherche légitime retourne des résultats"""
        r = client.get('/search?q=Security')
        assert r.status_code == 200
        assert b'Security' in r.data

    def test_search_empty_query_works(self, client):
        """Une recherche vide ne plante pas"""
        r = client.get('/search?q=')
        assert r.status_code == 200

    def test_comments_post_clean_content(self, auth_client):
        """Un commentaire propre est bien enregistré et affiché"""
        content = 'This is a clean comment with <b>bold</b>.'
        auth_client.post('/comments', data={'content': content})
        r = auth_client.get('/comments')
        assert b'clean comment' in r.data
        assert b'<b>bold</b>' in r.data

    def test_profile_update_works(self, auth_client):
        """Mise à jour de profil fonctionne pour les champs autorisés"""
        r = auth_client.post('/profile/update', data={
            'username': 'alice_updated',
            'bio': 'Updated bio'
        }, follow_redirects=True)
        assert r.status_code == 200

    def test_my_orders_returns_data(self, auth_client):
        """L'endpoint /api/my/orders retourne les commandes de l'utilisateur"""
        r = auth_client.get('/api/my/orders')
        assert r.status_code == 200
        data = r.get_json()
        assert isinstance(data, list)

    def test_hello_page_displays_name(self, client):
        """La page hello affiche le nom passé en paramètre"""
        r = client.get('/hello?name=Alice')
        assert r.status_code == 200
        assert b'Alice' in r.data
