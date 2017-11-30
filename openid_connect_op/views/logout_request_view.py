from urllib.parse import quote

from django.http.response import HttpResponseForbidden, HttpResponseRedirect
from django.views import View
from ratelimit.mixins import RatelimitMixin

from django.conf import settings

from openid_connect_op.models import OpenIDToken


class LogoutRequestView(RatelimitMixin, View):
    ratelimit_key = 'ip'
    ratelimit_rate = '10/m'
    ratelimit_block = True
    ratelimit_method = 'ALL'

    def dispatch(self, request, *args, **kwargs):
        id_token_hint = request.GET.get('id_token_hint', None)
        post_logout_redirect_uri = request.GET.get('post_logout_redirect_uri', '/')
        state = request.GET.get('state', None)

        if not id_token_hint:
            return HttpResponseForbidden('Must supply id_token_hint parameter')

        # remove all tokens associated with the user
        token = OpenIDToken.objects.filter(token_hash=OpenIDToken.get_token_hash(id_token_hint)).first()
        if not token:
            return HttpResponseForbidden('Invalid token')

        root_token = token.root_token
        root_token.related_tokens.all().delete()
        root_token.delete()

        # create next uri
        next_url = post_logout_redirect_uri
        if state:
            if '?' in next_url:
                next_url += '&'
            else:
                next_url += '?'
            next_url += 'state=' + quote(state)

        # and call logout on this server to remove any session we might have with the user
        return HttpResponseRedirect(settings.LOGOUT_URL + '?next=' + quote(next_url))
