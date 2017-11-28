import sys



if __name__ == '__main__':

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
                                      defaults=dict(first_name='Johnny',
                                                    last_name='English',
                                                    email='johnny@english.co.uk'))[0]
    u.set_password('test')
    u.save()

    # create an OpenIDClient
    # python-social-auth passes authentication data in POST data
    from openid_connect_op.models import OpenIDClient
    from django.conf import settings
    client = OpenIDClient.objects.update_or_create(
        client_id=settings.KEY,
        defaults = dict(redirect_uris=settings.SERVER_URL + '/complete/test/',
                        client_auth_type=OpenIDClient.CLIENT_AUTH_TYPE_POST)
    )[0]

    client.set_client_secret(settings.SECRET)
    client.save()

    print('Will use redirect uri "%s"' % client.redirect_uris)

    args = ['manage.py', 'runserver']
    args.extend(sys.argv[1:])
    execute_from_command_line(args)
