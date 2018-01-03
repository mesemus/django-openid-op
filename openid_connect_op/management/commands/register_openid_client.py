try:
    import secrets
except ImportError:
    import openid_connect_op.utils.secrets_backport as secrets

import jwcrypto.jwk as jwk
from django.core.management import BaseCommand

from openid_connect_op.models import OpenIDClient


class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument('--redirect-url',
                            help='A set of urls separated by whitespace '
                                 'to which the authorization server can redirect to after authorization')
        parser.add_argument('--server-name',
                            help='Human name of the server')
        parser.add_argument('--auth-type',
                            help='Authentication type. Currently only basic or post are supported',
                            default='basic')
        parser.add_argument('--list',
                            help='List all registered clients', action="store_true")


    def handle(self, *args, **kwargs):

        if kwargs['list']:
            self.list()
            return

        if not kwargs['auth_type'] or not kwargs['server_name'] or not kwargs['redirect_url']:
            print("Required arguments: auth-type, server-name, redirect-url")
            return

        if kwargs['auth_type'] == 'basic':
            client_auth_type = OpenIDClient.CLIENT_AUTH_TYPE_BASIC
        elif kwargs['auth_type'] == 'post':
            client_auth_type = OpenIDClient.CLIENT_AUTH_TYPE_POST
        else:
            raise Exception('Only "post" or "basic" are supported for auth-type parameter')

        client_id     = secrets.token_urlsafe(64)
        client_secret = secrets.token_urlsafe(64)

        client = OpenIDClient.objects.get_or_create(client_id=client_id,
                                                    defaults={
                                                        'client_auth_type': client_auth_type,
                                                        'client_name': kwargs['server_name'],
                                                        'redirect_uris': kwargs['redirect_url']
                                                    })[0]
        client.set_client_secret(client_secret)
        client.save()

        print("""
Registration successfull, please configure the server with:
     Client ID (KEY in settings.py for python-social-auth)        : %s
     Client Secret (SECRET in settings.py for python-social-auth) : %s
""" % (client_id, client_secret))

    def list(self):
        for client in OpenIDClient.objects.all():
            print("client_id        ", client.client_id)
            print("human name       ", client.client_name)
            print("redirect_uris    ", client.redirect_uris)
            print("client auth      ", client.client_auth_type)
            print()