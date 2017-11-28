from django.conf import settings
from social_core.backends.open_id_connect import OpenIdConnectAuth


class ConfiguredOpenIdConnectAuth(OpenIdConnectAuth):
    OIDC_ENDPOINT = settings.SERVER_URL
    STATE_PARAMETER = False
    REDIRECT_STATE = False
    name = 'test'

    def get_or_create_state(self):
        return '123'