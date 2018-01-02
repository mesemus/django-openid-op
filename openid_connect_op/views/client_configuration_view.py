from django.http import HttpResponseForbidden, JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from ratelimit.mixins import RatelimitMixin

from openid_connect_op.decorators import access_token_required
from openid_connect_op.models import OpenIDToken
from openid_connect_op.views import OAuthRequestMixin
from openid_connect_op.views.dynamic_registration_view import DynamicClientRegistrationView

try:
    import secrets
except ImportError:
    import openid_connect_op.utils.secrets_backport as secrets


class ClientConfigurationView(RatelimitMixin, OAuthRequestMixin, View):
    ratelimit_key = 'ip'
    ratelimit_rate = '10/m'
    ratelimit_block = True
    ratelimit_method = 'ALL'

    @method_decorator(csrf_exempt)
    @method_decorator(access_token_required())
    def dispatch(self, request, *args, **kwargs):
        return super().dispatch(request, *args, **kwargs)

    def get(self, request, client_id=None):
        if request.openid_access_token and \
                        request.openid_access_token.token_type != OpenIDToken.TOKEN_TYPE_CLIENT_CONFIGURATION_TOKEN:
            return HttpResponseForbidden('Can not use this token to access client configuration view')
        if request.openid_access_token.client.client_id != client_id:
            return HttpResponseForbidden('This token has not been issued for the client identified by client_id %s' % client_id)

        client = request.openid_access_token.client
        # note: we are deviating from the spec that says that
        # "the Client Read Request itself SHOULD NOT cause changes to the Client's registered Metadata values"
        # The reason is that the client secret is never stored in plain in this implementation, only as a hash
        # and it must be returned - so we need to generate a new value
        new_client_secret = secrets.token_urlsafe(32)
        client.set_client_secret(new_client_secret)
        client.save()

        resp = DynamicClientRegistrationView.make_registration_response(request, client, new_client_secret)
        return JsonResponse(resp)
