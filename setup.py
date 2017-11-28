from setuptools import setup

README = """
"""

setup(
    name='django-openid-op',
    version='0.1',
    packages=[
        'openid_connect_op',
        'openid_connect_op.management.commands',
        'openid_connect_op.migrations',
        'openid_connect_op.utils',
        'openid_connect_op.views',
    ],
    description='A django database based implementation of a subset of openid protocol, targeted at python3.6 and django 1.11+',
    long_description=README,
    author='Mirek Simek',
    author_email='miroslav.simek@gmail.com',
    url='https://github.com/mesemus/django-openid-op',
    license='MIT',
    install_requires=[
        'Django>=1.11',
        'pycryptodomex',
        'django-jsonfield',
        'django-ratelimit',
        'python-jwt'
    ],
    tests_require=[
        'tox',
        'pytest',
        'pytest-django',
        'pytest_matrix',
        'pytest-runner',
        'pytest-env',
        'social-auth-app-django',
        'pyjwkest'
    ],
    extras_require={
        'dev': [
            'sphinx',
            'tox',
            'pytest',
            'pytest-django',
            'pytest_matrix',
            'pytest-runner',
            'pytest-env',
            'social-auth-app-django',
            'pyjwkest'
        ]
    }
)
