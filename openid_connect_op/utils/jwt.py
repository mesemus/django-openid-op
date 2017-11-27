import datetime
from functools import lru_cache

import python_jwt as jwt
import jwcrypto.jwk as jwk
from django.conf import settings


class JWTTools:

    @staticmethod
    def generate_jwt(payload):
        cipher = getattr(settings, 'OPENID_JWT_CIPHER', 'RS256')
        return jwt.generate_jwt(payload, JWTTools.load_key(settings.OPENID_JWT_PRIVATE_KEY),
                                cipher)

    @staticmethod
    def validate_jwt(token):
        return jwt.verify_jwt(token, JWTTools.load_key(settings.OPENID_JWT_PUBLIC_KEY), ['RS256'])

    @staticmethod
    @lru_cache(maxsize=8)
    def load_key(path):
        with open(path, 'rb') as f:
            return jwk.JWK.from_pem(f.read())

