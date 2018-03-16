from setuptools import setup, find_packages

README = """
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

For more details see https://github.com/mesemus/django-openid-op
"""

setup(
    name='django-openid-op',
    version='0.2.1',
    packages=find_packages(exclude='tests'),
    include_package_data=True,
    description='A django database based implementation of a subset of openid protocol, targeted at python3.6 and django 1.11+',
    long_description=README,
    author='Mirek Simek',
    author_email='miroslav.simek@gmail.com',
    url='https://github.com/mesemus/django-openid-op',
    license='MIT',
    classifiers=[
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 3 - Alpha',

        # Indicate who your project is intended for
        'Intended Audience :: Developers',

        # Pick your license as you wish (should match "license" above)
        'License :: OSI Approved :: MIT License',

        # Specify the Python versions you support here. In particular, ensure
        # that you indicate whether you support Python 2, Python 3 or both.
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ],

    install_requires=[
        'Django>=1.11<2',
        'pycryptodomex',
        'django-jsonfield',
        'django-ratelimit',
        'python-jwt',
        'django-modeltranslation',
        'django-bleach',
        'requests'
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
