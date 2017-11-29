[![Build Status](https://travis-ci.org/mesemus/django-openid-op.svg?branch=master)](https://travis-ci.org/mesemus/django-openid-op)
[![Coverage](https://codecov.io/gh/mesemus/django-openid-op/branch/master/graph/badge.svg)](https://codecov.io/gh/mesemus/django-openid-op)
<!---

 [![Requirements Status](https://requires.io/github/mesemus/django-openid-idp/requirements.svg?branch=master)](https://requires.io/github/mesemus/django-openid-idp/requirements/?branch=master)
 [![Test report](https://img.shields.io/badge/tests-report-blue.svg)](https://mesemus.github.io/django-openid-idp/test_report.html)
 [![Coverage report](https://img.shields.io/badge/coverage-report-blue.svg)](https://mesemus.github.io/django-openid-idp/htmlcov/index.html)
 [![Docs](https://readthedocs.org/projects/pip/badge/)](http://django-openid-idp.readthedocs.io/en/latest/)
-->

Under development, please do not use yet.

# django-openid-op

This django application provides an implementation of OpenID Connect identity server
(OpenID provider). You can use it, for example, for building centralized authorization
server to which clients connect via the OpenID or OAuth2.0 protocol.

This library is compatible with python-social-auth package that can be used
as an OpenID client to access this server.

The following features of the OpenID Connect specification are implemented:

   * Basic profile from the OpenID Connect Core, including JWT signing
   * Subset of OpenID Connect Dynamic Registration
   * Subset of OpenID Content Discovery

Setting up
==========

Authorization server
--------------------

This library prefers Python 3.6 as it depends on ```secrets``` module.
If running in python 3.5, a backported version of ```secrets``` module 
from python 3.6.1 is used.

1. Set up virtualenv and create the authorization_server project

TODO: add pip 

```bash

cd /tmp
mkdir test
cd test

virtualenv --python=python3.6 venv-server
source venv-server/bin/activate
pip install django-openid-op

django-admin startproject authorization_server
(cd authorization_server; django-admin startapp web)

```

2. Edit the ```authorization_server/authorization_server/settings.py``` file and append the following lines to the end of the file:

```python

INSTALLED_APPS += [
    'openid_connect_op',
    'web'
]

APPEND_SLASH = False
```

3. Run ```python authorization_server/manage.py migrate```

4. Create keys that will be used to sign tokens:

```bash
python authorization_server/manage.py create_jwt_keys
```

5. Check that the server runs so far
```bash
python authorization_server/manage.py runserver
google-chrome http://localhost:8000/
```

6. Modify ```authorization_server/authorization_server/urls.py```

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

mkdir -p authorization_server/web/templates/registration
nano authorization_server/web/templates/registration/login.html
```
and put there standard logging template from django docs:
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

8. Create a sample user

```bash
python authorization_server/manage.py createsuperuser
Username (leave blank to use 'simeki'): admin
Email address: admin@example.com
Password:
Password (again):
Superuser created successfully.
```

Try to log in at ```http://localhost:8000/login```.

Congratulations, you have successfully set up an OpenID Connect
authentication server.

Client web server
-----------------

1. Run in another shell:

```bash

virtualenv --python=python3.6 venv-client
source venv-client/bin/activate
pip install django social-auth-app-django

django-admin startproject web_server
(cd web_server; django-admin startapp web)
```


2. In the authorization server's shell, register the newly created web server

```python
python authorization_server/manage.py register_openid_client \
      --redirect-url 'http://localhost:9000/complete/openid/' \
      --server-name  'My test server' \
      --auth-type post

> Registration successfull, please configure the server with:
>     Client ID (KEY in settings.py): aaaaaaa
>     Client Secret (SECRET in settings.py): bbbbbb
```

3. Edit the ```web_server/web_server/settings.py``` file and append the following lines to the end of the file:

```python

    AUTHENTICATION_BACKENDS = (
        'web.backends.OpenIdConnect',
        'django.contrib.auth.backends.ModelBackend',
    )

    INSTALLED_APPS += [
        'social_django',
        'web'
    ]

    # url where authorization_server lives
    OIDC_ENDPOINT = 'http://127.0.0.1:8000'

    KEY = 'aaaaaaa'
    SECRET = 'bbbbbb'

    LOGIN_URL = '/login/openid/'

```

4. Edit ```web_server/web/backends.py```:

```python
from django.conf import settings
from social_core.backends.open_id_connect import OpenIdConnectAuth

class OpenIdConnect(OpenIdConnectAuth):
    OIDC_ENDPOINT = settings.OIDC_ENDPOINT
    name = 'openid'
```

5. Create the index page (optionally):

```bash

mkdir -p web_server/web/templates
nano web_server/web/templates/base.html
```

```html
<html>
    <body>
        {% block content %} {% endblock %}
    </body>
</html>
```

```bash
nano web_server/web/templates/index.html
```

```html
{% extends "base.html" %}
{% block content %}
    <h1>Hello!</h1>
    {% if not user.is_anonymous %}
        <p>
            Your name is {{ user.first_name }} {{ user.last_name }}, username {{ user.username }}, email {{ user.email }}
        </p>
    {% else %}
        <p>
            Would you like to <a href="/login/openid/?next=/">log in</a>?
        </p>
    {% endif %}
{% endblock %}
```

```bash
nano web_server/web/views.py
```

```python
from django.views.generic import TemplateView

class IndexView(TemplateView):
    template_name = 'index.html'
```

```bash
nano web_server/web_server/urls.py
```

```python
from django.conf.urls import url
from django.contrib import admin
import web.views

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^/$', web.views.IndexView.as_view()),
]
```

6. Start the server and go to the index page or ```http://localhost:9000/login/openid/```

```bash
python web_server/manage.py runserver localhost:9000
```

See docs and API at http://django-openid-op.readthedocs.io/en/latest/
