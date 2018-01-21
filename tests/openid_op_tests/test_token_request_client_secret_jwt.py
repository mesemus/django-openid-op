import datetime
import json
from urllib.parse import urlencode, splitquery, parse_qs

import pytest
from django.contrib.auth.models import User
from django.core.management import call_command

from openid_connect_op.models import OpenIDClient, OpenIDToken
from openid_connect_op.utils.jwt import JWTTools
try:
    import secrets
except ImportError:
    import openid_connect_op.utils.secrets_backport as secrets

import jwcrypto.jwk as jwk


@pytest.mark.django_db
class TestTokenRequestClientSecretJWT:

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
            client_auth_type=OpenIDClient.CLIENT_AUTH_TYPE_SECRET_JWT,
        )
        ret.set_client_secret('b')
        ret.save()
        return ret

    def test_logged_user(self, client, client_config, user, settings):
        code = self.get_authorization_code(client, client_config, user)

        token = {
            'iss': client_config.client_id,
            'sub': client_config.client_id,
            'aud': ['http://testserver/openid/token'],
        }
        jwt_token = JWTTools.generate_jwt(token, client_config, datetime.timedelta(seconds=60),
                                          from_client=client_config)

        resp = client.get('/openid/token?' + urlencode({
            'redirect_uri': client_config.redirect_uris,
            'grant_type': 'authorization_code',
            'code': code,
            'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
            'client_assertion': jwt_token
        }))

        self.check_token_response(settings, client_config, resp)

    @staticmethod
    def check_token_response(settings, client_config, resp, sub='a'):
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
        assert payload['sub'] == sub  # username
        assert payload['iss'] == 'http://testserver/'

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
