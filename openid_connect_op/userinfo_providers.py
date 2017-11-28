from collections import defaultdict

import itertools

from django.utils.functional import cached_property
from django.utils.module_loading import import_string


class UserInfoProvider:
    """
    A provider for userinfo claims.
    """

    def get_claims(self, db_access_token):
        """
        Returns userinfo claims.

        This call must be idempotent.

        :param db_access_token:     an instance of OpenIDToken of the user whose claims should be returned
        :return:                    a dictionary of claims.
        """
        return {}


#
# OpenID Connect spec: default scopes and claims:
#
#  profile:
#      name, family_name, given_name, middle_name, nickname, preferred_username,
#      profile, picture, website, gender, birthdate, zoneinfo, locale, and updated_at.
# email
#      email, email_verified
# address
#      address
# phone
#      phone_number, phone_number_verified
#


class UserInfoProviderRegistry:
    """
    registry of UserInfoProvider instances
    """

    DEFAULT_SCOPE_CLAIMS = {
        'profile': ['name', 'family_name', 'given_name', 'middle_name', 'nickname', 'preferred_username',
                    'profile', 'picture', 'website', 'gender', 'birthdate', 'zoneinfo', 'locale', 'updated_at'],
        'email':   ['email', 'email_verified'],
    }

    DEFAULT_CLAIM_PROVIDERS = {
        'name'              : ['openid_connect_op.userinfo_providers.DjangoProfileProvider'],
        'family_name'       : ['openid_connect_op.userinfo_providers.DjangoProfileProvider'],
        'given_name'        : ['openid_connect_op.userinfo_providers.DjangoProfileProvider'],
        'preferred_username': ['openid_connect_op.userinfo_providers.DjangoProfileProvider'],
        'email'             : ['openid_connect_op.userinfo_providers.DjangoEmailProvider'],
        'sub'               : ['openid_connect_op.userinfo_providers.DjangoProfileProvider']
    }

    def __init__(self, user_scope_claims, user_claim_providers):
        self.scope_claims = {}
        self.scope_claims.update(self.DEFAULT_SCOPE_CLAIMS)
        self.scope_claims.update(user_scope_claims)
        self.claim_providers = self._load(user_claim_providers, self.DEFAULT_CLAIM_PROVIDERS)

    @cached_property
    def supported_scopes(self):
        return list(sorted(self.scope_claims.keys()))

    @cached_property
    def supported_claims(self):
        return list(sorted(self.claim_providers.keys()))

    @staticmethod
    def _load(user_handlers, default_handlers):
        ret = defaultdict(list)
        cache = {}
        for name, handler_classes in itertools.chain(user_handlers.items(), default_handlers.items()):
            handler_list = ret[name]
            if not isinstance(handler_classes, list) and not isinstance(handler_classes, tuple):
                raise AttributeError('Scope or Claim providers mapping must be in the form of '
                                     'dict(scope_name=list of provider classes), where provider class is '
                                     'either python class or its fully qualified name')
            for clz in handler_classes:
                if clz not in cache:
                    if isinstance(clz, str):
                        cache[clz] = import_string(clz)()
                    else:
                        cache[clz] = clz()
                handler_list.append(cache[clz])

        return ret

    def get_claims(self, db_access_token, scopes, claims):
        claim_values = {}
        claim_names = set(claims)
        claim_names.add('sub')
        for scope in scopes:
            claim_names.update(self.scope_claims.get(scope, []))

        cache = {}
        for claim in claim_names:
            if claim in self.claim_providers:
                for provider in self.claim_providers[claim]:
                    if provider not in cache:
                        provider_data = provider.get_claims(db_access_token, claim)
                        cache[provider] = provider_data
                    else:
                        provider_data = cache[provider]

                    if provider_data is not None:
                        if claim not in provider_data:
                            raise ValueError('Provider "%s" registered for claim "%s" has returned different claim!')
                        if provider_data[claim]:
                            # set only claim with value
                            claim_values[claim] = provider_data[claim]
                        break

        return claim_values


class DjangoProfileProvider(UserInfoProvider):
    def get_claims(self, db_access_token, scope_or_claim=None):
        user = db_access_token.user

        return {
            'name': user.get_full_name(),
            'family_name': user.last_name,
            'given_name': user.first_name,
            'preferred_username': user.username,
            'sub': user.username
            # 'middle_name' not set on django user,
            # 'nickname' not set on django user,
            # 'profile' not set on django user,
            # 'picture' not set on django user,
            # 'website' not set on django user,
            # 'gender' not set on django user,
            # 'birthdate' not set on django user,
            # 'zoneinfo' not set on django user,
            # 'locale' not set on django user,
            # 'updated_at' not set on django user.
        }


class DjangoEmailProvider(UserInfoProvider):
    def get_claims(self, db_access_token, scope_or_claim=None):
        user = db_access_token.user

        return {
            'email' : user.email
            # 'email_verified' not set on django user,
        }
