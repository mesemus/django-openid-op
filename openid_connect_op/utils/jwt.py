import datetime
from functools import lru_cache

import python_jwt as jwt
import jwcrypto.jwk as jwk
from django.conf import settings


class JWTTools:

    @staticmethod
    def generate_jwt(payload):
        from openid_connect_op.models import OpenIDKey, OpenIDClient
        cipher = getattr(settings, 'OPENID_JWT_CIPHER', 'RS256')
        return jwt.generate_jwt(payload,
                                jwk.JWK.from_pem(OpenIDClient.self_instance().get_key(OpenIDKey.JWK_RSA_PRIVATE_KEY)),
                                cipher)

    @staticmethod
    def validate_jwt(token):
        from openid_connect_op.models import OpenIDKey, OpenIDClient
        cipher = getattr(settings, 'OPENID_JWT_CIPHER', 'RS256')
        return jwt.verify_jwt(token,
                              jwk.JWK.from_pem(OpenIDClient.self_instance().get_key(OpenIDKey.JWK_RSA_PUBLIC_KEY)),
                              [cipher])

    @staticmethod
    def get_jwks():
        from openid_connect_op.models import OpenIDKey, OpenIDClient
        return jwk.JWK.from_pem(OpenIDClient.self_instance().get_key(OpenIDKey.JWK_RSA_PUBLIC_KEY)).export_public()

