import base64
from functools import wraps

from django.http.response import HttpResponseForbidden
from django.utils import timezone
from django.utils.decorators import available_attrs

from openid_connect_op.models import OpenIDToken


def get_access_token_from_auth_header(auth_header):
    auth_header = auth_header.strip()
    if not auth_header.startswith('Bearer '):
        raise AttributeError('Not a Bearer token')
    return auth_header[7:]


def get_access_token_from_post_data(request):
    post_data = request.POST
    if request.content_type != 'application/x-www-form-urlencoded':
        return None
    if 'access_token' not in post_data:
        return None
    return post_data['access_token']


def get_access_token_from_uri_query(get_data):
    if 'access_token' not in get_data:
        return None
    return get_data['access_token']


def extract_access_token(request, forbidden_on_not_present):
    auth_header = request.META.get('HTTP_AUTHORIZATION', None)
    access_token = None
    try:
        if auth_header is not None:
            access_token = get_access_token_from_auth_header(auth_header)
        if request.method == 'POST' and not access_token:
            access_token = get_access_token_from_post_data(request)
        if not access_token:
            access_token = get_access_token_from_uri_query(request.GET)
        if not access_token:
            if forbidden_on_not_present:
                return HttpResponseForbidden('No access token provided')
            else:
                return None
        try:
            db_access_token = OpenIDToken.objects.get(token_hash=OpenIDToken.get_token_hash(access_token))
            if db_access_token.expiration < timezone.now():
                return HttpResponseForbidden('Expired access token')
            return db_access_token
        except OpenIDToken.DoesNotExist:
            return HttpResponseForbidden('Provided access token not found')
    except BaseException as e:
        return HttpResponseForbidden('Access error: %s' % e)


def access_token_required(func):
    """
    Check that access token is present on the request and is valid. If not, returns HttpResponseForbidden.
    request is annotated with the database access token, i.e. isinstance(req.openid_access_token, OpenIDToken) == True
    """
    @wraps(func, assigned=available_attrs(func))
    def inner(request, *args, **kwargs):
        db_access_token = extract_access_token(request, True)
        if isinstance(db_access_token, HttpResponseForbidden):
            return db_access_token
        request.openid_access_token = db_access_token
        return func(request, *args, **kwargs)
    return inner


__all__ = ('access_token_required', )
