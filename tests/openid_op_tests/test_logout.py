import base64
import json
from urllib.parse import urlencode, splitquery, parse_qs

import pytest
import time
from django.contrib.auth.models import User
from django.core.management import call_command

from openid_connect_op.models import OpenIDClient, OpenIDToken
from openid_connect_op.utils.jwt import JWTTools

BASIC_AUTH = 'Basic ' + base64.b64encode('test:b'.encode('utf-8')).decode('ascii')


@pytest.mark.django_db
class TestLogoutRequest:

    @pytest.fixture(autouse=True)
    def init_jwk(self):
        call_command('create_jwt_keys')

    @pytest.fixture
    def user(self):
        return User.objects.create(username='a')

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

    def test_user_logout(self, client, client_config, user, settings):
        code = self.get_authorization_code(client, client_config, user)
        resp = client.get('/openid/token?' + urlencode({
            'redirect_uri': client_config.redirect_uris,
            'grant_type': 'authorization_code',
            'code': code,
        }), HTTP_AUTHORIZATION=BASIC_AUTH)

        access_token, id_token = self.check_token_response(settings, client_config, resp)

        resp = client.get('/openid/logout?' + urlencode({
            'id_token_hint': id_token,
            'post_logout_redirect_uri': 'https://example.com',
            'state': '2345',
        }))

        assert resp.status_code == 302
        assert resp.url == '/django/logout/?next=https%3A//example.com%3Fstate%3D2345'

    def test_no_id_token_logout(self, client, client_config, user, settings):
        resp = client.get('/openid/logout?' + urlencode({
            'post_logout_redirect_uri': 'https://example.com',
            'state': '2345',
        }))

        assert resp.status_code == 403
        assert resp.content == b'Must supply id_token_hint parameter'

    def test_bad_id_token_logout(self, client, client_config, user, settings):
        resp = client.get('/openid/logout?' + urlencode({
            'id_token_hint': '123456789',
            'post_logout_redirect_uri': 'https://example.com',
            'state': '2345',
        }))

        assert resp.status_code == 403
        assert resp.content == b'Invalid token'

    @staticmethod
    def check_token_response(settings, client_config, resp):
        assert resp.status_code == 200
        data = json.loads(resp.content.decode('utf-8'))
        assert 'access_token' in data
        assert data['token_type'] == 'Bearer'
        assert 'refresh_token' in data
        assert data['expires_in'] == settings.OPENID_DEFAULT_ACCESS_TOKEN_TTL
        assert 'id_token' in data
        database_at = OpenIDToken.objects.get(token_hash=OpenIDToken.get_token_hash(data['access_token']))
        assert database_at.user.username == 'a'
        assert database_at.client == client_config
        assert database_at.token_type == OpenIDToken.TOKEN_TYPE_ACCESS_BEARER_TOKEN
        database_rt = OpenIDToken.objects.get(token_hash=OpenIDToken.get_token_hash(data['refresh_token']))
        assert database_rt.user.username == 'a'
        assert database_rt.client == client_config
        assert database_rt.token_type == OpenIDToken.TOKEN_TYPE_REFRESH_TOKEN
        # validate id token
        header, payload = JWTTools.validate_jwt(data['id_token'])
        assert header['alg'] == 'RS256'
        assert header['typ'] == 'JWT'
        assert payload['exp'] == int(payload['exp'])
        assert payload['iat'] == int(payload['iat'])
        assert payload['aud'] == ['test']
        assert payload['sub'] == 'a'  # username
        assert payload['iss'] == 'http://testserver/'

        return data['access_token'], data['id_token']

    @staticmethod
    def get_authorization_code(client, client_config, user):
        client.force_login(user)
        resp = client.get('/openid/authorize?' + urlencode({
            'redirect_uri': client_config.redirect_uris,
            'client_id': 'test',
            'scope': 'openid',
            'response_type': 'code'
        }))
        assert resp.status_code == 302
        redirect_server, redirect_query = splitquery(resp.url)
        assert redirect_server == 'http://localhost:8000/complete/test/'
        redirect_query = parse_qs(redirect_query)
        assert redirect_query['state'] == ['1234']
        assert 'code' in redirect_query
        code = redirect_query['code'][0]
        return code
