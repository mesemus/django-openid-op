import datetime
from functools import lru_cache

import python_jwt as jwt
import jwcrypto.jwk as jwk
from django.conf import settings

from os import urandom
from jwcrypto.jws import JWS
from jwcrypto.common import base64url_encode, json_encode, json_decode
from calendar import timegm


# need to add "kid" header which the original python_jwt can not do
from openid_connect_op.models import OpenIDClient


def generate_jwt_patched(claims, priv_key=None,
                         algorithm='PS512', lifetime=None, expires=None,
                         not_before=None,
                         jti_size=16, extra_headers={}):
    """
    Generate a JSON Web Token.

    :param claims: The claims you want included in the signature.
    :type claims: dict

    :param priv_key: The private key to be used to sign the token. Note: if you pass ``None`` then the token will be returned with an empty cryptographic signature and :obj:`algorithm` will be forced to the value ``none``.
    :type priv_key: `jwcrypto.jwk.JWK <https://jwcrypto.readthedocs.io/en/latest/jwk.html>`_

    :param algorithm: The algorithm to use for generating the signature. ``RS256``, ``RS384``, ``RS512``, ``PS256``, ``PS384``, ``PS512``, ``ES256``, ``ES384``, ``ES512``, ``HS256``, ``HS384``, ``HS512`` and ``none`` are supported.
    :type algorithm: str

    :param lifetime: How long the token is valid for.
    :type lifetime: datetime.timedelta

    :param expires: When the token expires (if :obj:`lifetime` isn't specified)
    :type expires: datetime.datetime

    :param not_before: When the token is valid from. Defaults to current time (if ``None`` is passed).
    :type not_before: datetime.datetime

    :param jti_size: Size in bytes of the unique token ID to put into the token (can be used to detect replay attacks). Defaults to 16 (128 bits). Specify 0 or ``None`` to omit the JTI from the token.
    :type jti_size: int

    :rtype: unicode
    :returns: The JSON Web Token. Note this includes a header, the claims and a cryptographic signature. The following extra claims are added, per the `JWT spec <http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html>`_:

    - **exp** (*IntDate*) -- The UTC expiry date and time of the token, in number of seconds from 1970-01-01T0:0:0Z UTC.
    - **iat** (*IntDate*) -- The UTC date and time at which the token was generated.
    - **nbf** (*IntDate*) -- The UTC valid-from date and time of the token.
    - **jti** (*str*) -- A unique identifier for the token.
    """
    header = {
        'typ': 'JWT',
        'alg': algorithm if priv_key else 'none'
    }
    header.update(extra_headers)

    claims = dict(claims)

    now = datetime.datetime.utcnow()

    if jti_size:
        claims['jti'] = base64url_encode(urandom(jti_size))

    claims['nbf'] = timegm((not_before or now).utctimetuple())
    claims['iat'] = timegm(now.utctimetuple())

    if lifetime:
        claims['exp'] = timegm((now + lifetime).utctimetuple())
    elif expires:
        claims['exp'] = timegm(expires.utctimetuple())

    if header['alg'] == 'none':
        signature = ''
    else:
        token = JWS(json_encode(claims))
        token.add_signature(priv_key, protected=header)
        signature = json_decode(token.serialize())['signature']

    return u'%s.%s.%s' % (
        base64url_encode(json_encode(header)),
        base64url_encode(json_encode(claims)),
        signature
    )


class JWTTools:

    @staticmethod
    def generate_jwt(payload, for_client=None, ttl=None, from_client=None):
        if for_client is None:
            sign_alg = 'RS256'
        elif for_client.client_auth_type == OpenIDClient.CLIENT_AUTH_TYPE_SECRET_JWT:
            sign_alg = 'HS256'
        else:
            sign_alg = for_client.client_registration_data.get('id_token_signed_response_alg', 'RS256')

        return JWTTools.generate_jwt_with_sign_alg(payload, sign_alg, ttl=ttl, client=from_client)

    @staticmethod
    def generate_jwt_with_sign_alg(payload, sign_alg, ttl=None, client=None):
        from openid_connect_op.models import OpenIDClient
        if not client:
            client = OpenIDClient.self_instance()
        if client.client_auth_type == client.CLIENT_AUTH_TYPE_SECRET_JWT:
            sign_key = jwk.JWK(kty="oct", use="sig", alg="HS256", k=base64url_encode(client.client_hashed_secret))
            extra_headers = {}
            alg = 'HS256'
        else:
            sign_key = client.get_key(sign_alg)
            extra_headers = {
                'kid': sign_key.key_id
            }
            alg = sign_key._params['alg']

        return generate_jwt_patched(payload,
                                    sign_key,
                                    alg,
                                    extra_headers=extra_headers,
                                    lifetime=ttl)

    @staticmethod
    def validate_jwt(token, client=None):
        from openid_connect_op.models import OpenIDClient
        if client is None:
            client = OpenIDClient.self_instance()

        if client.client_auth_type == OpenIDClient.CLIENT_AUTH_TYPE_SECRET_JWT:
            key = jwk.JWK(kty="oct", use="sig", alg="HS256", k=base64url_encode(client.client_hashed_secret))
            return jwt.verify_jwt(token, key, ['HS256'], checks_optional=True)

        header, __ = jwt.process_jwt(token)
        key = client.get_key(alg=header.get('alg', 'RS256'), kid=header.get('kid', None))
        return jwt.verify_jwt(token, key, [key._params.get('alg', 'RS256')], checks_optional=True)

    @staticmethod
    def unverified_jwt_payload(token):
        return jwt.process_jwt(token)[1]