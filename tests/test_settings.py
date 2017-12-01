import os

SECRET_KEY = 'fake-key'
INSTALLED_APPS = [
    'modeltranslation',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'django_bleach',

    'openid_connect_op',
    'tests',
]

ROOT_URLCONF = 'tests.urls'
USE_TZ = True
USE_I18N = True

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': 'db.sqlite3',
    }
}

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
    'tests.middleware.RequestLoggerMiddleware'
]

DEBUG = True

STATIC_URL = '/static/'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.contrib.auth.context_processors.auth',
                'django.template.context_processors.debug',
                'django.template.context_processors.i18n',
                'django.template.context_processors.media',
                'django.template.context_processors.static',
                'django.template.context_processors.tz',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]


# OpenID server

APPEND_SLASH = False

# test client
RUNNING_TEST_SERVER_CLIENT = False
if 'TEST_SERVER_CLIENT' in os.environ:
    RUNNING_TEST_SERVER_CLIENT = True

    print("Running in test server with python-social-auth")

    AUTHENTICATION_BACKENDS = (
        'tests.backends.ConfiguredOpenIdConnectAuth',
        'django.contrib.auth.backends.ModelBackend',
    )

    INSTALLED_APPS += [
        'social_django'
    ]

    # make sure this is the same url as the one used for runserver
    SERVER_URL = 'http://127.0.0.1:8000'

    KEY = 'openid_test_client_id'
    SECRET = 'openid_test_client_secret'


LOGIN_URL = '/django/login/'
LOGOUT_URL = '/django/logout/'

LANGUAGES = (
    ('en', 'English'),
    ('cs', 'Czech')
)
