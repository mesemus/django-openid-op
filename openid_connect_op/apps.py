from django.apps import AppConfig
from django.utils.translation import ugettext_lazy as _

from openid_connect_op.userinfo_providers import UserInfoProviderRegistry


class OpenIDConnectOPApp(AppConfig):
    name = 'openid_connect_op'
    verbose_name = _('OpenID Connect Provider')

    def ready(self):
        from django.conf import settings

        if not getattr(settings, 'OPENID_USERINFO_PROVIDERS', None):
            settings.OPENID_USERINFO_PROVIDERS = \
                UserInfoProviderRegistry(getattr(settings, 'OPENID_SCOPE_CLAIMS', {}),
                                         getattr(settings, 'OPENID_CLAIM_PROVIDERS', {}))

        if not hasattr(settings, 'OPENID_USER_CONSENT_VIEW'):
            settings.OPENID_USER_CONSENT_VIEW = 'test:consent'

        if not hasattr(settings, 'OPENID_DEFAULT_ACCESS_TOKEN_TTL'):
            settings.OPENID_DEFAULT_ACCESS_TOKEN_TTL = 3600

        if not hasattr(settings, 'OPENID_DEFAULT_REFRESH_TOKEN_TTL'):
            settings.OPENID_DEFAULT_REFRESH_TOKEN_TTL = 3600 * 24

        if not hasattr(settings, 'OPENID_CONNECT_OP_DB_ENCRYPT_KEY'):
            key = settings.SECRET_KEY
            while len(key)<16:
                key += key
            settings.OPENID_CONNECT_OP_DB_ENCRYPT_KEY = key.encode('utf-8')[:16]