import base64
import json
from urllib.parse import splitquery, parse_qs, urlencode

import pytest
from django.contrib.auth.models import User
from django.core.management import call_command

from openid_connect_op.models import OpenIDClient


@pytest.mark.django_db
class TestUserInfo:

    @pytest.fixture(autouse=True)
    def init_jwk(self):
        call_command('create_jwt_keys')

    @pytest.fixture
    def user(self):
        return User.objects.create(
            username='a',
            first_name='A',
            last_name='B',
            email='a@b.com')

    @pytest.fixture()
    def client_config(self):
        redirect_uri = 'http://localhost:8000/complete/test/?state=1234'
        ret = OpenIDClient.objects.create(
            client_id='test',
            redirect_uris=redirect_uri,
            client_auth_type=OpenIDClient.CLIENT_AUTH_TYPE_BASIC,
        )
        ret.set_client_secret('b')
        ret.save()
        return ret

    @staticmethod
    def get_access_code(client, client_config, user, extra_scopes, extra_claims):
        client.force_login(user)
        resp = client.get('/openid/authorize?' + urlencode({
            'redirect_uri': client_config.redirect_uris,
            'client_id': 'test',
            'scope': '%s %s' % ('openid', ' '.join(extra_scopes)),
            'claims': ' '.join(extra_claims),
            'response_type': 'code'
        }))
        assert resp.status_code == 302
        redirect_server, redirect_query = splitquery(resp.url)
        assert redirect_server == 'http://localhost:8000/complete/test/'
        redirect_query = parse_qs(redirect_query)
        assert redirect_query['state'] == ['1234']
        assert 'code' in redirect_query
        code = redirect_query['code'][0]

        resp = client.get('/openid/token?' + urlencode({
            'redirect_uri': client_config.redirect_uris,
            'grant_type': 'authorization_code',
            'code': code,
        }), HTTP_AUTHORIZATION='Basic ' + base64.b64encode('test:b'.encode('utf-8')).decode('ascii'))

        data = json.loads(resp.content.decode('utf-8'))
        return data['access_token']

    def test_no_userinfo_claims(self, client, client_config, user):
        access_code = self.get_access_code(client, client_config, user, {}, {})

        resp = client.get('/openid/userinfo',
                          HTTP_AUTHORIZATION='Bearer ' + access_code)

        assert resp.status_code == 200
        data = json.loads(resp.content.decode('utf-8'))
        assert data == {'sub': 'a'}

    def test_profile_scope(self, client, client_config, user):
        access_code = self.get_access_code(client, client_config, user, {'profile'}, {})

        resp = client.get('/openid/userinfo',
                          HTTP_AUTHORIZATION='Bearer ' + access_code)

        assert resp.status_code == 200
        data = json.loads(resp.content.decode('utf-8'))
        assert data == {
            'sub': 'a',
            'name': 'A B',
            'family_name': 'B',
            'given_name': 'A',
            'preferred_username': 'a'
        }

    def test_profile_email_scope(self, client, client_config, user):
        access_code = self.get_access_code(client, client_config, user, {'profile', 'email'}, {})

        resp = client.get('/openid/userinfo',
                          HTTP_AUTHORIZATION='Bearer ' + access_code)

        assert resp.status_code == 200
        data = json.loads(resp.content.decode('utf-8'))
        assert data == {
            'sub': 'a',
            'name': 'A B',
            'family_name': 'B',
            'given_name': 'A',
            'preferred_username': 'a',
            'email': 'a@b.com',
        }

    def test_email_scope(self, client, client_config, user):
        access_code = self.get_access_code(client, client_config, user, {'email'}, {})

        resp = client.get('/openid/userinfo',
                          HTTP_AUTHORIZATION='Bearer ' + access_code)

        assert resp.status_code == 200
        data = json.loads(resp.content.decode('utf-8'))
        assert data == {
            'sub': 'a',
            'email': 'a@b.com',
        }

    def test_email_claim(self, client, client_config, user):
        access_code = self.get_access_code(client, client_config, user, {}, {'email'})

        resp = client.get('/openid/userinfo',
                          HTTP_AUTHORIZATION='Bearer ' + access_code)

        assert resp.status_code == 200
        data = json.loads(resp.content.decode('utf-8'))
        assert data == {
            'sub': 'a',
            'email': 'a@b.com',
        }

    def test_name_claims(self, client, client_config, user):
        access_code = self.get_access_code(client, client_config, user, {}, {'family_name', 'given_name'})

        resp = client.get('/openid/userinfo',
                          HTTP_AUTHORIZATION='Bearer ' + access_code)

        assert resp.status_code == 200
        data = json.loads(resp.content.decode('utf-8'))
        assert data == {
            'sub': 'a',
            'family_name': 'B',
            'given_name': 'A',
        }

    def test_allowed_claims_via_scope(self, client, client_config, user):
        client_config.allowed_scopes = ['profile']
        client_config.save()

        access_code = self.get_access_code(client, client_config, user, {'profile', 'email'}, {})

        resp = client.get('/openid/userinfo',
                          HTTP_AUTHORIZATION='Bearer ' + access_code)

        assert resp.status_code == 200
        data = json.loads(resp.content.decode('utf-8'))
        assert data == {
            'sub': 'a',
            'name': 'A B',
            'family_name': 'B',
            'given_name': 'A',
            'preferred_username': 'a'
        }


    def test_allowed_claims_via_name(self, client, client_config, user):
        client_config.allowed_claims = ['name']
        client_config.save()

        access_code = self.get_access_code(client, client_config, user, {'profile', 'email'}, {})

        resp = client.get('/openid/userinfo',
                          HTTP_AUTHORIZATION='Bearer ' + access_code)

        assert resp.status_code == 200
        data = json.loads(resp.content.decode('utf-8'))
        assert data == {
            'sub': 'a',
            'name': 'A B',
        }