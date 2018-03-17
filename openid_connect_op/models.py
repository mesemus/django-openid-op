import datetime
import hashlib
import logging

import re
from django.conf import settings
from django.db.models import Count, Sum
from jsonfield.fields import JSONField
from jwcrypto.jwk import JWKSet

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

    client_code = models.CharField(max_length=32, null=True, blank=True)
    client_name = models.CharField(max_length=128)

    allowed_scopes = JSONField(null=True, blank=True,
                               verbose_name='List of allowed scopes. If None, all scopes are allowed')

    allowed_claims = JSONField(null=True, blank=True,
                               verbose_name='List of allowed claims. If None, '
                                            'all claims from allowed scopes are returned')

    sub_hash = models.CharField(max_length=256, null=True, blank=True,
                                verbose_name="If set, <<sub>> values (that is, username) will be concatenated with this value and sha256")

    client_registration_data = JSONField(default={})

    jwks = models.TextField(default='{}')

    def make_sub(self, original_sub):
        if not self.sub_hash:
            return original_sub
        return hashlib.sha256((original_sub + self.sub_hash).encode('utf-8')).hexdigest()

    def set_client_secret(self, password):
        if password is None:
            raise AttributeError('Password can not be empty')
        if self.client_auth_type == self.CLIENT_AUTH_TYPE_SECRET_JWT:
            # need secret in plain text !
            self.client_hashed_secret = password
        else:
            hasher = get_hasher('default')
            salt = hasher.salt()
            self.client_hashed_secret = hasher.encode(password, salt)

    def check_client_secret(self, raw_password):
        if self.client_auth_type == self.CLIENT_AUTH_TYPE_SECRET_JWT:
            return self.client_hashed_secret == raw_password

        # taken from User
        def setter(raw_password):
            self.set_client_secret(raw_password)
            self.save(update_fields=["client_hashed_secret"])

        return check_password(raw_password, self.client_hashed_secret, setter)

    def has_user_agreement(self, user, auto_approve=True):
        """
        Checks if the user has approved sending his data (including, for example, roles, phone number etc.)
        to this client

        :param user:    django User
        :return:        True if user has approved sending the data (and client's usage policy), False otherwise
        """
        has_agreement = True

        for agreement in self.get_unsigned_agreements(user, auto_approve=auto_approve):
            if agreement.obligatory:
                has_agreement = False

        return has_agreement

    def get_unsigned_agreements(self, user, auto_approve=False):
        """
        Return all OpenIDAgreements for this client that user has not signed.
        :param user:            The user to check
        :param auto_approve:    If True, all approvals that can be signed automatically will be
        :return:                Generator of OpenIDAgreement
        """
        agreements_user_has_not_signed = \
            self.agreements.annotate(
                has_me=Sum(
                    models.Case(
                        models.When(user_agreements__user=user, then=1),
                        default=0,
                        output_field=models.IntegerField()))).filter(has_me=0)

        if not auto_approve:
            yield from agreements_user_has_not_signed

        for agreement in agreements_user_has_not_signed:
            # try to auto approve
            if agreement.can_auto_approve(user.username):
                OpenIDUserAgreement.objects.create(agreement=agreement, user=user, agreed_on=timezone.now())
            else:
                yield agreement

    def get_user_agreements(self, user):
        # return all the agreements that are applicable to the user. In the current version, that means all
        return self.agreements.all()

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

    def get_keys(self):
        if self.jwks:
            return JWKSet.from_json(self.jwks)
        return JWKSet()

    def get_key(self, alg=None, kid=None):
        jwks = self.get_keys()
        ret = []
        for key in jwks['keys']:
            if alg and 'alg' in key._params and key._params['alg'] != alg:
                continue
            if kid and key.key_id != kid:
                continue
            ret.append(key)
        if len(ret) > 1:
            raise AttributeError('Have more keys with the given alg %s and kid %s' % (alg, kid))

        if not ret:
            raise AttributeError('Could not find key with alg %s and kid %s' % (alg, kid))

        return ret[0]

    def __str__(self):
        return self.client_name


class OpenIDAgreement(models.Model):
    client = models.ForeignKey(OpenIDClient, on_delete=models.CASCADE, related_name='agreements')
    text = models.TextField()
    obligatory = models.BooleanField()

    allowed_scopes = JSONField(null=True, blank=True,
                               verbose_name='List of allowed scopes for this agreement.')

    allowed_claims = JSONField(null=True, blank=True,
                               verbose_name='List of allowed claims for this agreement')

    username_auto_agreement_regexp = models.CharField(null=True, blank=True, max_length=256,
                                                      verbose_name='Usernames matching this regexp will have this '
                                                                   'agreement automatically agreed to')

    def can_auto_approve(self, username):
        return self.username_auto_agreement_regexp and re.match(self.username_auto_agreement_regexp, username)


class OpenIDUserAgreement(models.Model):
    agreement = models.ForeignKey(OpenIDAgreement, on_delete=models.CASCADE, related_name='user_agreements')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='user_agreements')
    agreed_on = models.DateTimeField()
    agreed_by_user = models.BooleanField(default=False, verbose_name='If set to False, '
                                                                     'the agreement was created automatically, '
                                                                     'otherwise it was created explicitly by user')


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
    root_token = models.ForeignKey('openid_connect_op.OpenIDToken', related_name='related_tokens',
                                   on_delete=models.PROTECT,
                                   null=True, blank=True)

    @staticmethod
    def get_token_hash(token):
        """
        Returns a sha256 hash for the given token. The hash is used as token_hash attribute

        :param token:   token
        :return:        sha256 hexdigest
        """
        return hashlib.sha256(token.encode('ascii')).hexdigest()

    @property
    def expired(self):
        return self.expiration < timezone.now()

    TOKEN_TYPE_AUTH = 'AUTH'
    TOKEN_TYPE_ACCESS_BEARER_TOKEN = 'ACCT'
    TOKEN_TYPE_REFRESH_TOKEN = 'REFR'
    TOKEN_TYPE_ID_TOKEN = 'ID'
    TOKEN_TYPE_CLIENT_DYNAMIC_REGISTRATION = 'CDR'
    TOKEN_TYPE_CLIENT_CONFIGURATION_TOKEN = 'CCF'

    INFINITE_TTL = 99999999999

    @classmethod
    def create_token(cls, client, token_type, token_data, ttl, user, root_db_token=None, token=None):
        """
        Creates a time-limited token of a given type associated with user

        :param client:          for which client is the token created/registered
        :param token_type:      type of the token
        :param token_data:      extra JSON data associated with the token
        :param ttl:             ttl in seconds beginning now
        :param user:            user with whom the token is associated
        :return:                created token as urlsafe string
        """
        if not token:
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
