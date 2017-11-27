import base64
import json
from urllib.parse import urlencode, splitquery, parse_qs

import pytest
from django.contrib.auth.models import User

from openid_connect_op.models import OpenIDClient, TokenStore
from openid_connect_op.utils.jwt import JWTTools


@pytest.mark.django_db
class TestAuthenticationRequest:
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
            client_username='a'
        )
        ret.set_client_password('b')
        ret.save()
        return ret

    def test_logged_user(self, client, client_config, user):
        code = self.get_authorization_code(client, client_config, user)
        resp = client.get('/token/?' + urlencode({
            'redirect_uri': client_config.redirect_uris,
            'grant_type': 'authorization_code',
            'code': code,
        }),
                          HTTP_AUTHORIZATION='Basic ' + base64.b64encode('a:b'.encode('utf-8')).decode('ascii'))
        print(resp.content)
        assert resp.status_code == 200
        data = json.loads(resp.content.decode('utf-8'))
        assert 'access_token' in data
        assert data['token_type'] == 'Bearer'
        assert 'refresh_token' in data
        assert data['expires_in'] == 3600
        assert 'id_token' in data
        database_at = TokenStore.objects.get(token_hash=TokenStore.get_token_hash(data['access_token']))
        assert database_at.user.username == 'a'
        assert database_at.client == client_config
        assert database_at.token_type == TokenStore.TOKEN_TYPE_ACCESS_BEARER_TOKEN

        database_rt = TokenStore.objects.get(token_hash=TokenStore.get_token_hash(data['refresh_token']))
        assert database_rt.user.username == 'a'
        assert database_rt.client == client_config
        assert database_rt.token_type == TokenStore.TOKEN_TYPE_REFRESH_TOKEN

        # validate id token
        header, payload = JWTTools.validate_jwt(data['id_token'])
        assert header['alg'] == 'RS256'
        assert header['typ'] == 'JWT'
        assert payload['exp'] == int(payload['exp'])
        assert payload['iat'] == int(payload['iat'])
        assert payload['aud'] == ['test']
        assert payload['sub'] == 'a'            # username
        assert payload['iss'] == 'http://testserver/'

    def get_authorization_code(self, client, client_config, user):
        client.force_login(user)
        resp = client.get('/authorize/?' + urlencode({
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
        code = redirect_query['code']
        return code
