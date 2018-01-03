from django.http.response import JsonResponse, HttpResponse
from django.views import View

from openid_connect_op.models import OpenIDClient
from openid_connect_op.utils.jwt import JWTTools


class JWKSView(View):
    def get(self, request, *args, **kwargs):
        client = OpenIDClient.objects.get(client_id=OpenIDClient.SELF_CLIENT_ID)
        keys = client.get_keys()
        for k in list(keys['keys']):
            if not k.has_public:
                keys['keys'].remove(k)
        return HttpResponse(keys.export(private_keys=False), content_type='application/json')