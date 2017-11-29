import datetime
import hashlib
import logging

from django.conf import settings
from jsonfield.fields import JSONField

from openid_connect_op.utils.crypto import CryptoTools

try:
    import secrets
except ImportError:
    import openid_connect_op.utils.secrets_backport as secrets

from urllib.parse import urlparse, splitquery, parse_qs

import jsonfield
from django.contrib.auth.hashers import get_hasher, check_password
from django.contrib.auth.models import User
from django.db import models
from django.utils import timezone

log = logging.getLogger(__file__)


class OpenIDClient(models.Model):
    """
    An abstract model that implements OpenID client configuration (client = someone who requests access token)
    """

    #
    # ID of the client, the client sends this id in the access request
    #
    client_id = models.CharField(max_length=128, unique=True)
    SELF_CLIENT_ID = '---self---'

    #
    # After logging in, browser is redirected to one of these URIs (separated by newline).
    # The actual redirection URI is sent by the client, OpenID server verifies that the URI
    # is among these configured ones. For detail of how this decision is made, see check_redirect_url
    # method.
    #
    redirect_uris = models.TextField(default='')

    CLIENT_AUTH_TYPE_BASIC = 'basic'
    CLIENT_AUTH_TYPE_POST = 'post'
    CLIENT_AUTH_TYPE_SECRET_JWT = 'sjwt'
    CLIENT_AUTH_TYPE_PRIVATE_KEY_JWT = 'pkjwt'
    CLIENT_AUTH_TYPE_NONE = 'none'
    CLIENT_AUTH_TYPE_INVALID = 'invalid'

    client_auth_type = models.CharField(max_length=8, choices=(
        (CLIENT_AUTH_TYPE_BASIC, 'Basic Authentication'),
        (CLIENT_AUTH_TYPE_POST, 'Authentication data in POST request'),
        (CLIENT_AUTH_TYPE_SECRET_JWT, 'JSON Web token with pre-shared secret'),
        (CLIENT_AUTH_TYPE_PRIVATE_KEY_JWT, 'JSON Web token with public/private key'),
        (CLIENT_AUTH_TYPE_NONE, 'No client authentication performed'),
    ))

    client_hashed_secret = models.CharField(max_length=128)

    client_name = models.CharField(max_length=128)

    def set_client_secret(self, password):
        if password is None:
            raise AttributeError('Password can not be empty')
        hasher = get_hasher('default')
        salt = hasher.salt()
        self.client_hashed_secret = hasher.encode(password, salt)

    def check_client_secret(self, raw_password):
        # taken from User
        def setter(raw_password):
            self.set_client_secret(raw_password)
            self.save(update_fields=["client_hashed_password"])

        return check_password(raw_password, self.client_hashed_secret, setter)

    def has_user_approval(self, user):
        """
        Checks if the user has approved sending his data (including, for example, roles, phone number etc.)
        to this client

        :param user:    django User
        :return:        True if user has approved sending the data (and client's usage policy), False otherwise
        """
        return True

    def check_redirect_url(self, _redirect_uri):
        """
        Checks if the actual redirection uri is among the configured uris. If not, returns False.

        :param _redirect_uri: URI sent in the Authorization request
        :return:            True if it is among the configured URIs, False otherwise
        """
        part = urlparse(_redirect_uri)
        if part.fragment:
            log.debug("Can not contain fragment: %s", _redirect_uri)
            return False

        _base, _query = self.__split_base_query(_redirect_uri)

        for potential_redirect_uri in self.redirect_uris.split():
            redirect_uri_base, redirect_uri_query = self.__split_base_query(potential_redirect_uri)

            # The base of URI MUST exactly match the base
            if _base != redirect_uri_base:
                continue

            class NotFoundException(Exception):
                pass

            try:
                # every registered query component must exist in the
                # redirect_uri
                if redirect_uri_query:
                    for key, vals in redirect_uri_query.items():
                        if not _query or key not in _query:
                            raise NotFoundException()

                        for val in vals:
                            if val and val not in _query[key]:
                                raise NotFoundException()

                # and vice versa, every query component in the redirect_uri
                # must be registered
                if _query:
                    if redirect_uri_query is None:
                        raise NotFoundException()
                    for key, vals in _query.items():
                        if key not in redirect_uri_query:
                            raise NotFoundException()
                        for val in vals:
                            if redirect_uri_query[key]:
                                if val not in redirect_uri_query[key] and '' not in redirect_uri_query[key]:
                                    raise NotFoundException()
                # found it, so return True
                return True
            except NotFoundException:
                pass

        log.debug("%s Doesn't match any registered uris %s", _redirect_uri, self.redirect_uris)
        return False

    @staticmethod
    def __split_base_query(_redirect_uri):
        (_base, _query) = splitquery(_redirect_uri)
        if _query:
            _query = parse_qs(_query, keep_blank_values=True)
        return _base, _query

    @staticmethod
    def self_instance():
        return OpenIDClient.objects.get(client_id=OpenIDClient.SELF_CLIENT_ID)

    def get_key(self, key_type):
        return OpenIDKey.objects.get(client=self, key_type=key_type).key

class OpenIDToken(models.Model):
    """
        Store for issued tokens. Only the hash is stored, not the token itself.
    """
    client = models.ForeignKey(OpenIDClient, on_delete=models.CASCADE)
    token_hash = models.CharField(max_length=64, unique=True)
    token_type = models.CharField(max_length=4)
    token_data = jsonfield.JSONField(default={})
    expiration = models.DateTimeField()
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    root_token = models.ForeignKey('openid_connect_op.OpenIDToken', related_name='related_tokens', on_delete=models.PROTECT,
                                   null=True, blank=True)

    @staticmethod
    def get_token_hash(token):
        """
        Returns a sha256 hash for the given token. The hash is used as token_hash attribute

        :param token:   token
        :return:        sha256 hexdigest
        """
        return hashlib.sha256(token.encode('ascii')).hexdigest()

    TOKEN_TYPE_ACCESS_BEARER_TOKEN = 'ACCT'
    TOKEN_TYPE_REFRESH_TOKEN       = 'REFR'
    TOKEN_TYPE_ID_TOKEN            = 'ID'
    TOKEN_TYPE_CLIENT_DYNAMIC_REGISTRATION = 'CDR'

    @classmethod
    def create_token(cls, client, token_type, token_data, ttl, user, root_db_token=None):
        """
        Creates a time-limited token of a given type associated with user

        :param token_type:      type of the token
        :param token_data:      extra JSON data associated with the token
        :param ttl:             ttl in seconds beginning now
        :param user:            user with whom the token is associated
        :return:                created token as urlsafe string
        """
        token = secrets.token_urlsafe(64)
        token_hash = OpenIDToken.get_token_hash(token)
        db_token = OpenIDToken.objects.create(
            client=client,
            token_hash=token_hash,
            token_type=token_type,
            token_data=token_data,
            expiration=timezone.now() + datetime.timedelta(seconds=ttl)
                            if not isinstance(ttl, datetime.datetime) else ttl,
            user=user,
            root_token=root_db_token)

        return token, db_token


class OpenIDKey(models.Model):
    client = models.ForeignKey(OpenIDClient, on_delete=models.CASCADE)

    JWK_RSA_PUBLIC_KEY = 'jwk_rsa_public'
    JWK_RSA_PRIVATE_KEY = 'jwk_rsa_private'
    AES_KEY = 'aes'

    key_type = models.CharField(max_length=16, choices=(
        (JWK_RSA_PRIVATE_KEY, 'JWK RSA private key'),
        (JWK_RSA_PUBLIC_KEY, 'JWK RSA public key'),
        (AES_KEY, 'AES key')
    ))
    encrypted_key_value = models.BinaryField()

    @property
    def key(self):
        return CryptoTools.decrypt(self.encrypted_key_value,
                                   key=settings.OPENID_CONNECT_OP_DB_ENCRYPT_KEY)

    @key.setter
    def key(self, value):
        self.encrypted_key_value = OpenIDKey.encrypt_key(value)

    @staticmethod
    def encrypt_key(value):
        return CryptoTools.encrypt(value, key=settings.OPENID_CONNECT_OP_DB_ENCRYPT_KEY)