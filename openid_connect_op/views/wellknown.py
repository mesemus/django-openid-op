from django.conf import settings
from django.http.response import JsonResponse
from django.urls import reverse
from django.views import View


class WellKnownView(View):
    defaults = {
        "token_endpoint_auth_methods_supported":
            ["client_secret_basic", "private_key_jwt", "client_secret_jwt", "client_secret_post"],
        "response_types_supported":
            ["code"],
        "subject_types_supported":
            ["public", "pairwise"],
        "userinfo_signing_alg_values_supported":
            ["RS256"],
        "id_token_signing_alg_values_supported":
            ["RS256"],
        "display_values_supported":
            ["page"],
        "claim_types_supported":
            ["normal"],
        "claims_parameter_supported":
            False,
        "ui_locales_supported":
            ["en-US", "cs-CZ"]
    }
    extra = {}

    def get(self, request, *args, **kwargs):
        resp = {}
        print("returning wellknown")
        resp.update(self.defaults)
        resp.update(self.extra)
        resp['issuer'] = request.build_absolute_uri('/')
        resp['authorization_endpoint'] = request.build_absolute_uri(reverse('openid_connect_op:authorize'))
        resp['token_endpoint'] = request.build_absolute_uri(reverse('openid_connect_op:token'))
        resp['userinfo_endpoint'] = request.build_absolute_uri(reverse('openid_connect_op:userinfo'))
        resp['jwks_uri'] = request.build_absolute_uri(reverse('openid_connect_op:jwks'))
        resp['registration_endpoint'] = request.build_absolute_uri(reverse('openid_connect_op:register'))
        resp['end_session_endpoint'] = request.build_absolute_uri(reverse('openid_connect_op:logout'))

        for service_name, service_reverse in getattr(settings, 'OPENID_EXTRA_SERVICES', {}).items():
            resp[service_name] = request.build_absolute_uri(reverse(service_reverse))

        resp["scopes_supported"] = ['openid'] + settings.OPENID_USERINFO_PROVIDERS.supported_scopes
        resp["claims_supported"] = settings.OPENID_USERINFO_PROVIDERS.supported_claims + ['iss', 'auth_time', 'acr']

        return JsonResponse(resp)
