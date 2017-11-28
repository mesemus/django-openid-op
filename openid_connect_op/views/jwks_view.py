from django.http.response import JsonResponse, HttpResponse
from django.views import View

from openid_connect_op.utils.jwt import JWTTools


class JWKSView(View):
    def get(self, request, *args, **kwargs):
        return HttpResponse('{"keys": [%s]}' % JWTTools.get_jwks(), content_type='application/json')