from openid_connect_op.utils.crypto import CryptoTools

try:
    import secrets
except ImportError:
    import openid_connect_op.utils.secrets_backport as secrets

import jwcrypto.jwk as jwk
from django.conf import settings
from django.core.management import BaseCommand

from openid_connect_op.models import OpenIDClient, OpenIDKey


class Command(BaseCommand):
    def handle(self, *args, **kwargs):
        """
        Creates JWT keys at the location pointed by settings.OPENID_JWT_PRIVATE_KEY, settings.OPENID_JWT_PUBLIC_KEY
        """
        key = jwk.JWK.generate(kty='RSA', size=2048)
        priv_pem = key.export_to_pem(private_key=True, password=None)
        pub_pem = key.export_to_pem()
        aes = secrets.token_urlsafe(nbytes=16).encode('ascii')[:16]

        client = OpenIDClient.objects.get_or_create(client_id=OpenIDClient.SELF_CLIENT_ID,
                                                    defaults={
                                                        'client_auth_type': OpenIDClient.CLIENT_AUTH_TYPE_INVALID,
                                                        'client_name': 'This server'
                                                    })[0]

        OpenIDKey.objects.update_or_create(client=client, key_type=OpenIDKey.JWK_RSA_PUBLIC_KEY, defaults={
            'encrypted_key_value': OpenIDKey.encrypt_key(pub_pem)
        })

        OpenIDKey.objects.update_or_create(client=client, key_type=OpenIDKey.JWK_RSA_PRIVATE_KEY, defaults={
            'encrypted_key_value': OpenIDKey.encrypt_key(priv_pem)
        })

        OpenIDKey.objects.update_or_create(client=client, key_type=OpenIDKey.AES_KEY, defaults={
            'encrypted_key_value': OpenIDKey.encrypt_key(aes)
        })
