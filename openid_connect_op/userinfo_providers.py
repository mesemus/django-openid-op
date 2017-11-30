import inspect
from collections import defaultdict

import itertools

from django.utils.functional import cached_property
from django.utils.module_loading import import_string


class UserInfoProvider:
    """
    A provider for userinfo claims.
    """

    SCOPE_CLAIMS = {}

    def get_claims(self, db_access_token):
        """
        Returns userinfo claims.

        This call must be idempotent.

        :param db_access_token:     an instance of OpenIDToken of the user whose claims should be returned
        :return:                    a dictionary of claims.
        """
        return {}

    def get_scope_claims(self):
        return self.SCOPE_CLAIMS

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


class DjangoProfileProvider(UserInfoProvider):
    SCOPE_CLAIMS = {
        'profile': ['name', 'family_name', 'given_name', 'preferred_username'],
        # sub is not in a named scope, it is always added
        '': ['sub']
    }

    def get_claims(self, db_access_token, scope_or_claim=None):
        user = db_access_token.user

        return {
            'name': user.get_full_name(),
            'family_name': user.last_name,
            'given_name': user.first_name,
            'preferred_username': user.username,
            'sub': user.username,
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
    SCOPE_CLAIMS = {
        'email': ['email']
    }

    def get_claims(self, db_access_token, scope_or_claim=None):
        user = db_access_token.user

        return {
            'email': user.email
            # 'email_verified' not set on django user,
        }


class UserInfoProviderRegistry:
    """
    registry of UserInfoProvider instances
    """

    DEFAULT_CLAIM_PROVIDERS = [
        DjangoProfileProvider,
        DjangoEmailProvider
    ]

    def __init__(self, user_claim_providers):
        self.scope_claims = {}
        self.claim_providers = {}
        for provider in itertools.chain(user_claim_providers, self.DEFAULT_CLAIM_PROVIDERS):
            self.register_provider(provider)

    def register_provider(self, provider_class_or_classname_or_instance):
        if isinstance(provider_class_or_classname_or_instance, str):
            provider = import_string(provider_class_or_classname_or_instance)()
        elif inspect.isclass(provider_class_or_classname_or_instance):
            provider = provider_class_or_classname_or_instance()
        else:
            provider = provider_class_or_classname_or_instance

        for scope_name, claims in provider.get_scope_claims().items():
            if scope_name not in self.scope_claims:
                self.scope_claims[scope_name] = []
            for claim in claims:
                if claim not in self.scope_claims[scope_name]:
                    self.scope_claims[scope_name].append(claim)
                if claim not in self.claim_providers:
                    self.claim_providers[claim] = []
                self.claim_providers[claim].append(provider)

    @cached_property
    def supported_scopes(self):
        return [scope for scope in sorted(self.scope_claims.keys()) if scope]

    @cached_property
    def supported_claims(self):
        return list(sorted(self.claim_providers.keys()))

    def get_claims(self, db_access_token, scopes, claims):
        claim_values = {}
        claim_names = set(claims)
        for scope in scopes:
            claim_names.update(self.scope_claims.get(scope, []))
        # add all claims from the unnamed scope
        claim_names.update(self.scope_claims[''])

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

