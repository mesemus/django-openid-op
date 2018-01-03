import json

import pytest
import time
from django.core.management import call_command
import jwcrypto.jwk as jwk

from openid_connect_op.utils.jwt import JWTTools


@pytest.mark.django_db
class TestJWKS:

    @pytest.fixture(autouse=True)
    def init_jwk(self):
        call_command('create_jwt_keys')

    def test_get_jwks(self, client):
        resp = client.get('/openid/jwks')
        assert resp.status_code == 200
        data = json.loads(resp.content.decode('utf-8'))
        assert 'keys' in data
        assert len(data['keys']) >= 1
        for key in data['keys']:
            jwk.JWK(**key).export_public() == key

    def test_jwks_sign(self):
        payload = {
            'a': 'b',
            'exp': time.time() + 60
        }
        for alg in ('RS256', 'RS512', 'ES256', 'ES384', 'ES512'):
            token = JWTTools.generate_jwt_with_sign_alg(payload, alg)
            print(token)
            decrypted_payload = JWTTools.validate_jwt(token)[1]
            for extra in ('iat', 'jti', 'nbf'):
                if extra in decrypted_payload:
                    decrypted_payload.pop(extra)
            assert decrypted_payload == payload