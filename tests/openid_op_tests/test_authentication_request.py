import json
from urllib.parse import urlencode, parse_qs, splitquery

import pytest
from django.contrib.auth.models import User
from django.core.management import call_command

from openid_connect_op.models import OpenIDClient, OpenIDKey
from openid_connect_op.views.parameters import AuthenticationParameters


@pytest.mark.django_db
class TestAuthenticationRequest:
    @pytest.fixture(autouse=True)
    def init_jwk(self):
        call_command('create_jwt_keys')

    def test_no_redirect_uri_flow(self, client):
        resp = client.get('/openid/authorize')
        assert json.loads(resp.content.decode('utf-8')) == {
            "error": "invalid_request_uri",
            "error_description": "Required parameter with name \"redirect_uri\" is not present"}
        assert resp.status_code == 400

    def test_no_params_flow(self, client):
        resp = client.get('/openid/authorize?' + urlencode({
            'redirect_uri': 'http://localhost:8000/complete/test/?state=1234'
        }))
        assert resp.status_code == 302
        assert resp.url.startswith('http://localhost:8000/complete/test/')
        self.check_query(resp, {
            'state': ['1234'],
            'error': ['invalid_request_uri'],
            'error_description': ['Required parameter with name "client_id" is not present']
        })

    @staticmethod
    def check_query(resp, expected):
        query = parse_qs(splitquery(resp.url)[1])
        assert query == expected

    def test_unknown_client_id_flow(self, client):
        resp = client.get('/openid/authorize?' + urlencode({
            'redirect_uri': 'http://localhost:8000/complete/test/?state=1234',
            'client_id': '1'
        }))
        assert resp.status_code == 302
        self.check_query(resp, {
            'state': ['1234'],
            'error': ['invalid_request_uri'],
            'error_description': ['Required parameter with name "scope" is not present']
        })

    def test_no_response_type(self, client):
        resp = client.get('/openid/authorize?' + urlencode({
            'redirect_uri': 'http://localhost:8000/complete/test/?state=1234',
            'client_id': '1',
            'scope': 'openid'
        }))
        assert resp.status_code == 302
        self.check_query(resp, {
            'state': ['1234'],
            'error': ['invalid_request_uri'],
            'error_description': ['Required parameter with name "response_type" is not present']
        })

    def test_unsupported_response_type(self, client):
        resp = client.get('/openid/authorize?' + urlencode({
            'redirect_uri': 'http://localhost:8000/complete/test/?state=1234',
            'client_id': '1',
            'scope': 'openid',
            'response_type': 'unsupported_token'
        }))
        assert resp.status_code == 302
        self.check_query(resp, {
            'state': ['1234'],
            'error': ['invalid_request_uri'],
            'error_description': ['Value "unsupported_token" is not allowed for parameter '
                                  'response_type. Allowed values are "code", "id_token", "token"']
        })

    def test_unknown_client_id(self, client):
        resp = client.get('/openid/authorize?' + urlencode({
            'redirect_uri': 'http://localhost:8000/complete/test/?state=1234',
            'client_id': 'unknown',
            'scope': 'openid',
            'response_type': 'code'
        }))
        assert resp.status_code == 302
        self.check_query(resp, {
            'state': ['1234'],
            'error': ['unauthorized_client'],
            'error_description': ['The client is unauthorized to get authentication token']
        })

    @pytest.fixture()
    def client_config(self):
        redirect_uri = 'http://localhost:8000/complete/test/?state=1234'
        return OpenIDClient.objects.create(
            client_id='test',
            redirect_uris=redirect_uri
        )

    def test_redirect_to_login(self, client, client_config):
        resp = client.get('/openid/authorize?' + urlencode({
            'redirect_uri': client_config.redirect_uris,
            'client_id': 'test',
            'scope': 'openid',
            'response_type': 'code'
        }))
        self.check_is_redirect_to_login_page(resp)

    @staticmethod
    def check_is_redirect_to_login_page(resp):
        assert resp.status_code == 302

        # check that this is a url to the login server and there is a ?next=...
        login_server, login_query = splitquery(resp.url)
        assert login_server == '/accounts/login/'
        login_query = parse_qs(login_query)
        assert 'next' in login_query

        # parse the ?next=... and check that it goes back to the authorize endpoint with ?authp
        next_server, next_query = splitquery(login_query['next'][0])
        assert next_server == 'http://testserver/openid/authorize'
        next_query = parse_qs(next_query)
        assert 'authp' in next_query

        # check that ?authp param contains correctly encrypted value
        AuthenticationParameters.unpack(next_query['authp'][0].encode('utf-8'),
                                        key=OpenIDClient.self_instance().get_key(OpenIDKey.AES_KEY))

    @pytest.fixture
    def user(self):
        return User.objects.create(username='a')

    def test_logged_user(self, client, client_config, user):
        client.force_login(user)
        resp = client.get('/openid/authorize?' + urlencode({
            'redirect_uri': client_config.redirect_uris,
            'client_id': 'test',
            'scope': 'openid',
            'response_type': 'code'
        }))

        self.check_response_contains_code(resp)

    @staticmethod
    def check_response_contains_code(resp):
        assert resp.status_code == 302

        redirect_server, redirect_query = splitquery(resp.url)
        assert redirect_server == 'http://localhost:8000/complete/test/'
        redirect_query = parse_qs(redirect_query)
        assert redirect_query['state'] == ['1234']
        assert 'code' in redirect_query

        # check that ?code param contains correctly encrypted value
        AuthenticationParameters.unpack(redirect_query['code'][0].encode('utf-8'), prefix=b'AUTH',
                                        key=OpenIDClient.self_instance().get_key(OpenIDKey.AES_KEY))

    def test_require_new_login(self, client, client_config, user):
        client.force_login(user)
        resp = client.get('/openid/authorize?' + urlencode({
            'redirect_uri': client_config.redirect_uris,
            'client_id': 'test',
            'scope': 'openid',
            'response_type': 'code',
            'prompt': 'login'
        }))
        self.check_is_redirect_to_login_page(resp)

    def test_prompt_none_ok(self, client, client_config, user):
        client.force_login(user)
        resp = client.get('/openid/authorize?' + urlencode({
            'redirect_uri': client_config.redirect_uris,
            'client_id': 'test',
            'scope': 'openid',
            'response_type': 'code',
            'prompt': 'none'
        }))

        self.check_response_contains_code(resp)

    def test_prompt_none_failure(self, client, client_config, user):
        resp = client.get('/openid/authorize?' + urlencode({
            'redirect_uri': client_config.redirect_uris,
            'client_id': 'test',
            'scope': 'openid',
            'response_type': 'code',
            'prompt': 'none'
        }))
        assert resp.status_code == 302
        self.check_query(resp, {
            'state': ['1234'],
            'error': ['login_required'],
            'error_description': ['No prompt requested but user is not logged in']
        })

    def test_require_user_consent(self, client, client_config, user):
        client.force_login(user)
        resp = client.get('/openid/authorize?' + urlencode({
            'redirect_uri': client_config.redirect_uris,
            'client_id': 'test',
            'scope': 'openid',
            'response_type': 'code',
            'prompt': 'consent'
        }))
        self.check_is_redirect_to_consent_page(client_config, resp)

    @staticmethod
    def check_is_redirect_to_consent_page(client_config, resp):
        assert resp.status_code == 302

        # check that this is a url to the login server and there is a ?next=...
        consent_server, consent_query = splitquery(resp.url)
        assert consent_server == '/openid/consent/%s/' % client_config.id
        consent_query = parse_qs(consent_query)
        assert 'next' in consent_query

        # parse the ?next=... and check that it goes back to the authorize endpoint with ?authp
        next_server, next_query = splitquery(consent_query['next'][0])
        assert next_server == 'http://testserver/openid/authorize'
        next_query = parse_qs(next_query)
        assert 'authp' in next_query

        # check that ?authp param contains correctly encrypted value
        AuthenticationParameters.unpack(next_query['authp'][0].encode('utf-8'),
                                        key=OpenIDClient.self_instance().get_key(OpenIDKey.AES_KEY))
