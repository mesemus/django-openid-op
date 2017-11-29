import json

import pytest
from django.core.management import call_command


@pytest.mark.django_db
class TestWellKnownURL:

    @pytest.fixture(autouse=True)
    def init_jwk(self):
        call_command('create_jwt_keys')

    def test_get_wellknown(self, client):
        resp = client.get('/.well-known/openid-configuration')
        assert resp.status_code == 200
        data = json.loads(resp.content.decode('utf-8'))
        print(data)
        assert data == {
            'authorization_endpoint': 'http://testserver/openid/authorize',
            'claim_types_supported': ['normal'],
            'claims_parameter_supported': False,
            'claims_supported': [
                'email', 'family_name', 'given_name', 'name', 'preferred_username',
                'sub', 'iss', 'auth_time', 'acr'
            ],
            'display_values_supported': ['page'],
            'id_token_signing_alg_values_supported': ['RS256'],
            'issuer': 'http://testserver/',
            'jwks_uri': 'http://testserver/openid/jwks',
            'response_types_supported': ['code'],
            'scopes_supported': ['openid', 'email', 'profile'],
            'subject_types_supported': ['public', 'pairwise'],
            'token_endpoint': 'http://testserver/openid/token',
            'token_endpoint_auth_methods_supported': ['client_secret_basic'],
            'ui_locales_supported': ['en-US', 'cs-CZ'],
            'userinfo_signing_alg_values_supported': ['RS256'],
            'userinfo_endpoint': 'http://testserver/openid/userinfo'
        }
