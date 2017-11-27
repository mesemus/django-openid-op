from django.http.response import JsonResponse
from django.urls import reverse
from django.views import View


class WellKnownView(View):
    defaults = {
        "token_endpoint_auth_methods_supported":
            ["client_secret_basic"],
        "jwks_uri":
            "https://server.example.com/jwks.json",
        "scopes_supported":
            ["openid", "profile", "email", "address",
             "phone"
             ],
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
        "claims_supported":
            ["sub", "iss", "auth_time", "acr",
             "name", "given_name", "family_name", "nickname",
             "profile", "picture", "website",
             "email"
             ],
        "claims_parameter_supported":
            True,
        "ui_locales_supported":
            ["en-US", "cs-CZ"]
    }
    extra = {}

    def get(self, request, *args, **kwargs):
        resp = {}
        resp.update(self.defaults)
        resp.update(self.extra)
        resp['issuer'] = request.build_absolute_uri('/')
        resp['authorization_endpoint'] = request.build_absolute_uri(reverse('openid_connect_op:authorize'))
        resp['token_endpoint'] =         request.build_absolute_uri(reverse('openid_connect_op:token'))

        return JsonResponse(resp)
