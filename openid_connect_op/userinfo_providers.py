from collections import defaultdict

import itertools
from django.utils.module_loading import import_string


class UserInfoProvider:
    """
    A provider for userinfo claims.
    """

    def get_claims(self, db_access_token, scope_or_claim=None):
        """
        Returns userinfo claims for the given scope or claim name. Note: providers are registered for a scope/claim,
        so in most cases they do not need to check these scope or claim at runtime.

        This call must be idempotent.

        :param db_access_token:     an instance of OpenIDToken of the user whose userinfo should be returned
        :param scope_or_claim:      the scope or claim for which we are called
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

    DEFAULT_SCOPE_PROVIDERS = {
        'profile': ['openid_connect_op.userinfo_providers.DjangoProfileProvider'],
        'email':   ['openid_connect_op.userinfo_providers.DjangoEmailProvider'],
    }

    DEFAULT_CLAIM_PROVIDERS = {
        'name': ['openid_connect_op.userinfo_providers.DjangoProfileProvider'],
        'family_name': ['openid_connect_op.userinfo_providers.DjangoProfileProvider'],
        'given_name': ['openid_connect_op.userinfo_providers.DjangoProfileProvider'],
        'preferred_username': ['openid_connect_op.userinfo_providers.DjangoProfileProvider'],
        'email': ['openid_connect_op.userinfo_providers.DjangoEmailProvider']
    }

    def __init__(self, user_scope_providers, user_claim_providers):
        self.scope_providers = self._load(user_scope_providers, self.DEFAULT_SCOPE_PROVIDERS)
        self.claim_providers = self._load(user_claim_providers, self.DEFAULT_CLAIM_PROVIDERS)

    @staticmethod
    def _load(user_handlers, default_handlers):
        ret = defaultdict(list)

        for name, handler_classes in itertools.chain(user_handlers.items(), default_handlers.items()):
            handler_list = ret[name]
            if not isinstance(handler_classes, list) and not isinstance(handler_classes, tuple):
                raise AttributeError('Scope or Claim providers mapping must be in the form of '
                                     'dict(scope_name=list of provider classes), where provider class is '
                                     'either python class or its fully qualified name')
            for clz in handler_classes:
                if isinstance(clz, str):
                    clz = import_string(clz)
                handler_list.append(clz())

        return ret

    def get_claims(self, db_access_token, scopes, claims):
        claim_values = {}
        for scope in scopes:
            if scope in self.scope_providers:
                for provider in self.scope_providers[scope]:
                    for claim_name, claim_value in provider.get_claims(db_access_token, scope).items():
                        # do not overwrite already filled claims, put there only claims with values
                        if claim_name not in claim_values and claim_value:
                            claim_values[claim_name] = claim_value

        for claim in claims:
            if claim in self.claim_providers:
                for provider in self.claim_providers[claim]:
                    provider_data = provider.get_claims(db_access_token, claim)
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
