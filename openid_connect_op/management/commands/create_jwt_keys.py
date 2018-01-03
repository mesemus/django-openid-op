import json

try:
    import secrets
except ImportError:
    import openid_connect_op.utils.secrets_backport as secrets

import jwcrypto.jwk as jwk
from django.conf import settings
from django.core.management import BaseCommand

from openid_connect_op.models import OpenIDClient


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        """
        Creates JWT keys at the location pointed by settings.OPENID_JWT_PRIVATE_KEY, settings.OPENID_JWT_PUBLIC_KEY
        """
        jwks = jwk.JWKSet()

        jwks['keys'].add(jwk.JWK.generate(kty='RSA', alg='RS256', size=2048, kid=secrets.token_urlsafe(32)))
        jwks['keys'].add(jwk.JWK.generate(kty='RSA', alg='RS512', size=4096, kid=secrets.token_urlsafe(32)))
        jwks['keys'].add(jwk.JWK.generate(kty='EC', crv='P-256', alg='ES256', kid=secrets.token_urlsafe(32)))
        jwks['keys'].add(jwk.JWK.generate(kty='EC', crv='P-384', alg='ES384', kid=secrets.token_urlsafe(32)))
        jwks['keys'].add(jwk.JWK.generate(kty='EC', crv='P-521', alg='ES512', kid=secrets.token_urlsafe(32)))
        jwks['keys'].add(jwk.JWK.generate(kty='oct', alg='AES', size=16*8, kid=secrets.token_urlsafe(32)))

        client = OpenIDClient.objects.get_or_create(client_id=OpenIDClient.SELF_CLIENT_ID,
                                                    defaults={
                                                        'client_auth_type': OpenIDClient.CLIENT_AUTH_TYPE_INVALID,
                                                        'client_name': 'This server'
                                                    })[0]
        client.jwks = json.dumps(json.loads(jwks.export(private_keys=True)), indent=True)
        client.save()
        print(client.jwks)
