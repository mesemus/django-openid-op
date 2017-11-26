from setuptools import setup

README = """
"""


setup(
    name='django-openid-idp',
    version='0.1',
    packages=[
        'openid_idp',
    ],
    description='A django database based implementation of a subset of openid protocol, targeted at python3.6 and django 1.11+',
    long_description=README,
    author='Mirek Simek',
    author_email='miroslav.simek@gmail.com',
    url='https://github.com/mesemus/django-openid-idp',
    license='MIT',
    install_requires=[
        'Django>=1.11',
        'pycryptodomex',
    ],
    tests_require=[
        'tox',
        'pytest',
        'pytest-django',
        'pytest_matrix',
        'pytest-runner',
        'pytest-env',
        'python-social-auth',
        'social-auth-app-django',
        'pyjwkest'
    ],
    extras_require={
        'dev': [
            'sphinx'
        ]
    }
)
