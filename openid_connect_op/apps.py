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
                UserInfoProviderRegistry(getattr(settings, 'OPENID_SCOPE_PROVIDERS', {}),
                                         getattr(settings, 'OPENID_CLAIM_PROVIDERS', {}))
