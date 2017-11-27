import jwcrypto.jwk as jwk
from django.conf import settings
from django.core.management import BaseCommand


class Command(BaseCommand):

    def handle(self, *args, **kwargs):
        """
        Creates JWT keys at the location pointed by settings.OPENID_JWT_PRIVATE_KEY, settings.OPENID_JWT_PUBLIC_KEY
        """
        key = jwk.JWK.generate(kty='RSA', size=2048)
        priv_pem = key.export_to_pem(private_key=True, password=None)
        pub_pem = key.export_to_pem()

        with open(settings.OPENID_JWT_PRIVATE_KEY, 'wb') as f:
            f.write(priv_pem)

        with open(settings.OPENID_JWT_PUBLIC_KEY, 'wb') as f:
            f.write(pub_pem)