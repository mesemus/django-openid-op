import sys


def setup_sample_server():

    import os
    os.environ['TEST_SERVER_CLIENT'] = 'yes'
    os.environ['DJANGO_SETTINGS_MODULE'] = 'tests.test_settings'

    if os.path.exists('db.sqlite3'):
        os.remove('db.sqlite3')

    import django
    django.setup()

    from django.core.management import call_command
    from django.core.management import execute_from_command_line

    call_command('migrate')

    # create a sample user
    from django.contrib.auth.models import User
    u = User.objects.update_or_create(username='test',
                                      is_superuser=True,
                                      is_staff=True,
                                      defaults=dict(first_name='Johnny',
                                                    last_name='English',
                                                    email='johnny@english.co.uk'))[0]
    u.set_password('test')
    u.save()

    args = ['manage.py', 'create_jwt_keys']
    args.extend(sys.argv[1:])
    execute_from_command_line(args)

    # create an OpenIDClient
    # python-social-auth passes authentication data in POST data
    from openid_connect_op.models import OpenIDClient, OpenIDAgreement
    from django.conf import settings
    client = OpenIDClient.objects.update_or_create(
        client_id=settings.KEY,
        defaults = dict(redirect_uris=settings.SERVER_URL + '/complete/test/',
                        client_auth_type=OpenIDClient.CLIENT_AUTH_TYPE_POST),
        client_name='Sample OpenID RP'
    )[0]

    client.set_client_secret(settings.SECRET)
    client.save()

    OpenIDAgreement.objects.create(
        client = client,
        text = 'This is an obligatory agreement',
        obligatory = True,
        allowed_scopes = ['profile', 'email'],
        allowed_claims = None
    )

    OpenIDAgreement.objects.create(
        client = client,
        text = 'This is an optional agreement',
        obligatory = False,
        allowed_scopes = ['optional_scope'],
        allowed_claims = None
    )

    print('Will use redirect uri "%s"' % client.redirect_uris)



if __name__ == '__main__':
    setup_sample_server()