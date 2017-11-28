# section 4.1.3 of OAUTH 2.0
from django.conf import settings
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from ratelimit.mixins import RatelimitMixin

from openid_connect_op.decorators import access_token_required


class UserInfoView(RatelimitMixin, View):
    ratelimit_key = 'ip'
    ratelimit_rate = '10/m'
    ratelimit_block = True
    ratelimit_method = 'ALL'

    @method_decorator(csrf_exempt)
    @method_decorator(access_token_required)
    def dispatch(self, request, *args, **kwargs):
        token_data = request.openid_access_token.token_data
        claims = token_data['claims']
        scopes = token_data['scope']

        claim_values = settings.OPENID_USERINFO_PROVIDERS.get_claims(request.openid_access_token,
                                                                    scopes, claims)
        claim_values['sub'] = request.openid_access_token.user.username
        return JsonResponse(claim_values)
