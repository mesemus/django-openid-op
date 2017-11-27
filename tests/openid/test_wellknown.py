import json

import pytest


@pytest.mark.django_db
class TestWellKnownURL:
    def test_get_wellknown(self, client):
        resp = client.get('/.well-known/openid-configuration')
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert data == {'authorization_endpoint': 'http://testserver/openid/authorize',
                        'claim_types_supported': ['normal'],
                        'claims_parameter_supported': True,
                        'claims_supported': ['sub',
                                             'iss',
                                             'auth_time',
                                             'acr',
                                             'name',
                                             'given_name',
                                             'family_name',
                                             'nickname',
                                             'profile',
                                             'picture',
                                             'website',
                                             'email'],
                        'display_values_supported': ['page'],
                        'id_token_signing_alg_values_supported': ['RS256'],
                        'issuer': 'http://testserver/',
                        'jwks_uri': 'https://server.example.com/jwks.json',
                        'response_types_supported': ['code'],
                        'scopes_supported': ['openid', 'profile', 'email', 'address', 'phone'],
                        'subject_types_supported': ['public', 'pairwise'],
                        'token_endpoint': 'http://testserver/openid/token',
                        'token_endpoint_auth_methods_supported': ['client_secret_basic'],
                        'ui_locales_supported': ['en-US', 'cs-CZ'],
                        'userinfo_signing_alg_values_supported': ['RS256']}
