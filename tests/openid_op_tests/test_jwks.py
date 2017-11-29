import json

import pytest
from django.core.management import call_command
import jwcrypto.jwk as jwk

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

