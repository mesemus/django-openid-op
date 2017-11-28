SECRET_KEY = 'fake-key'
INSTALLED_APPS = [
    'django.contrib.contenttypes',
    'django.contrib.auth',
    'django.contrib.sessions',
    'social_django',
    'openid_connect_op',
    'tests',
]

ROOT_URLCONF = 'tests.urls'
USE_TZ = True

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
]

DEBUG = True

# OpenID server

OPENID_JWT_PRIVATE_KEY = 'jwt_private.pem'
OPENID_JWT_PUBLIC_KEY = 'jwt_public.pem'
OPENID_CONNECT_OP_AES_KEY = b'1234567890abcdef'
OPENID_USER_CONSENT_VIEW = 'test:consent'
OPENID_DEFAULT_ACCESS_TOKEN_TTL = 3600
OPENID_DEFAULT_REFRESH_TOKEN_TTL = 3600 * 24

APPEND_SLASH = False

# test client

AUTHENTICATION_BACKENDS = (
    'tests.backends.OpenIdConnectBackend',
    'django.contrib.auth.backends.ModelBackend',
)

OPENID_AUTHORIZATION_URL = ''
OPENID_ACCESS_TOKEN_URL = ''
OPENID_USER_DETAIL_URL = ''
OPENID_OIDC_URL = ''
