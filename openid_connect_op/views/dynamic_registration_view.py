# section 4.1.3 of OAUTH 2.0
import json
try:
    import secrets
except ImportError:
    import openid_connect_op.utils.secrets_backport as secrets

from django.http import JsonResponse
from django.http.response import HttpResponseForbidden, HttpResponseBadRequest
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from ratelimit.mixins import RatelimitMixin

from openid_connect_op.decorators import access_token_required
from openid_connect_op.models import OpenIDToken, OpenIDClient
from openid_connect_op.views import OAuthRequestMixin, OAuthError
from openid_connect_op.views.parameters import DynamicClientRegistrationParameters


class DynamicClientRegistrationView(RatelimitMixin, OAuthRequestMixin, View):
    ratelimit_key = 'ip'
    ratelimit_rate = '10/m'
    ratelimit_block = True
    ratelimit_method = 'ALL'

    @method_decorator(csrf_exempt)
    @method_decorator(access_token_required)
    def dispatch(self, request, *args, **kwargs):
        if request.openid_access_token.token_type != OpenIDToken.TOKEN_TYPE_CLIENT_DYNAMIC_REGISTRATION:
            return HttpResponseForbidden('Can not use this token to access dynamic registration view')
        if request.method != 'POST':
            return HttpResponseBadRequest('Only POST is allowed')

        try:
            self.parse_request_parameters(request, DynamicClientRegistrationParameters)

            client_id = secrets.token_urlsafe(32)
            client_secret = secrets.token_urlsafe(32)

            client = OpenIDClient.objects.create(
                client_id=client_id,
                redirect_uris='\n'.join(self.request_parameters.redirect_uris),
                client_auth_type=OpenIDClient.CLIENT_AUTH_TYPE_BASIC,
                client_name=self.request_parameters.client_name
            )
            client.set_client_secret(client_secret)
            client.save()

            resp = json.loads(request.body.decode('utf-8'))
            resp.update({
                "client_id": client_id,
                "client_secret": client_secret,
                "client_secret_expires_at": 0,
            })

            return JsonResponse(resp, status=201)

        except OAuthError as err:
            return self.oauth_send_answer(request, {
                'error': err.error,
                'error_description': err.error_description
            })
