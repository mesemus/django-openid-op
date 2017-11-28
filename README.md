<!--- [![Build Status](https://travis-ci.org/mesemus/django-openid-idp.svg?branch=master)](https://travis-ci.org/mesemus/django-openid-idp)
 [![Coverage](https://codecov.io/gh/mesemus/django-openid-idp/branch/master/graph/badge.svg)](https://codecov.io/gh/mesemus/django-openid-idp)
 [![Requirements Status](https://requires.io/github/mesemus/django-openid-idp/requirements.svg?branch=master)](https://requires.io/github/mesemus/django-openid-idp/requirements/?branch=master)
 [![Test report](https://img.shields.io/badge/tests-report-blue.svg)](https://mesemus.github.io/django-openid-idp/test_report.html)
 [![Coverage report](https://img.shields.io/badge/coverage-report-blue.svg)](https://mesemus.github.io/django-openid-idp/htmlcov/index.html)
 [![Docs](https://readthedocs.org/projects/pip/badge/)](http://django-openid-idp.readthedocs.io/en/latest/)
-->

Under development, please do not use yet.

# django-openid-op

This django application provides an implementation of OpenID Connect identity server
(OpenID provider). You can use it, for example, for building centralized logging
server to which clients connect via the OpenID or OAuth2.0 protocol.

This library is compatible with python-social-auth package that can be used
as an OpenID client to access this server.

From the OpenID Connect specification the following features are implemented:

   * Basic profile from the OpenID Connect Core, including JWKS signing
   * Subset of OpenID Connect Dynamic Registration
   * Subset of OpenID Content Discovery

Setting up
==========

This library requires Python 3.6 to work as it depends on ```secrets``` module

1. Set up virtualenv and create the login_server project

TODO: add pip 

```bash

cd /tmp
mkdir test
cd test

virtualenv --python=python3.6 venv-server
source venv-server/bin/activate
pip install git+https://github.com/mesemus/django-openid-op.git

django-admin startproject login_server
(cd login_server; django-admin startapp web)

```

2. Edit the ```login_server/login_server/settings.py``` file and append the following lines to the end of the file:

```python

INSTALLED_APPS += [
    'openid_connect_op',
    'web'
]

OPENID_JWT_PRIVATE_KEY = 'jwt_private.pem'
OPENID_JWT_PUBLIC_KEY = 'jwt_public.pem'
OPENID_CONNECT_OP_AES_KEY = b'1234567890abcdef'
OPENID_USER_CONSENT_VIEW = 'test:consent'
OPENID_DEFAULT_ACCESS_TOKEN_TTL = 3600
OPENID_DEFAULT_REFRESH_TOKEN_TTL = 3600 * 24

APPEND_SLASH = False
```

3. Run ```python login_server/manage.py migrate```

4. Create keys that will be used to sign tokens:

```bash
python login_server/manage.py create_jwt_keys
```

The files pointed by ```OPENID_JWT_PRIVATE_KEY``` and ```OPENID_JWT_PUBLIC_KEY``` will be created

5. Check that the server runs so far
```bash
python login_server/manage.py runserver
google-chrome http://localhost:8000/
```

6. Modify ```login_server/login_server/urls.py```

```python
# added ", include" here
from django.conf.urls import url, include
from django.contrib import admin

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    # added these lines
    url('^', include('openid_connect_op.urls')),
    url('^', include('django.contrib.auth.urls')),
]

```

This will create the following urls:

   * ```/.well-known/openid-configuration``` - URL that returns configuration of this OpenID provider according to RFC 5785
   * ```/openid/jwks``` - returns the public key that clients may use to validate received information
   * ```/openid/authorize```, ```/openid/token``` - OpenID authorization and token endpoints
   * ```/openid/userinfo``` - OpenID user information endpoint
   * ```/openid/register``` - Dynamic client registration service

Start the server and try to point Postman or browser to ```http://localhost:8000/.well-known/openid-configuration```
and ```http://localhost:8000/openid/jwks``` to check that the step above works.

7. Add login template

```bash

mkdir -p login_server/web/templates/registration
nano login_server/web/templates/registration/login.html
```
and put there
```html
<html>
  <body>
    {% if form.errors %}
    <p>Your username and password didn't match. Please try again.</p>
    {% endif %}

    {% if next %}
        {% if user.is_authenticated %}
        <p>Your account doesn't have access to this page. To proceed,
        please login with an account that has access.</p>
        {% else %}
        <p>Please login to see this page.</p>
        {% endif %}
    {% endif %}

    <form method="post" action="{% url 'login' %}">
        {% csrf_token %}
        <table>
        <tr>
            <td>{{ form.username.label_tag }}</td>
            <td>{{ form.username }}</td>
        </tr>
        <tr>
            <td>{{ form.password.label_tag }}</td>
            <td>{{ form.password }}</td>
        </tr>
        </table>

        <input type="submit" value="login" />
        <input type="hidden" name="next" value="{{ next }}" />
    </form>
  </body>
</html>
```

See docs and API at http://django-openid-op.readthedocs.io/en/latest/
