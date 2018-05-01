import django.dispatch

authorization_request_start = django.dispatch.Signal(providing_args=["request"])
"""
A signal that is sent before the processing of authorization token request
"""

authorization_request_finish = django.dispatch.Signal(providing_args=["request", "openid_client", "token"])
"""
A signal that is sent after the processing of authorization token request
"""

access_token_start = django.dispatch.Signal(providing_args=["request", "openid_client"])
"""
A signal that is sent before the processing of access token request
"""

access_token_finish = django.dispatch.Signal(providing_args=["request", "openid_client", "access_token", "refresh_token", "id_token"])
"""
A signal that is sent after the processing of access token request
"""

before_user_consent = django.dispatch.Signal(providing_args=["openid_client", "user"])
"""
A signal that is sent after the user is logged in but before the consent screen is shown. The signal is sent even
when the consent step is skipped, if it was signed previously. In that case, consent_already_signed is set to True.
If the signal listener returns an HttpResponse, this response is returned to the user agent instead of the standard 
openid redirection response. For example, user can be directed to a page that states that he/she has no rights 
to access the application.

Params:

openid_client : an instance of OpenID client that the user is trying to log into
user          : the user that is logging to
"""


after_user_consent = django.dispatch.Signal(providing_args=["openid_client", "user"])
"""
A signal that is sent after the user has accepted consent. If the consent has been accepted in a previous login, 
this signal is not sent. If the signal listener
returns an HttpResponse, this response is returned to the user agent instead of the standard openid redirection
response. For example, user can be directed to a page that states that he/she has no rights to access the application.
"""


before_userinfo_token = django.dispatch.Signal(providing_args=["openid_client", "userinfo_token", "user"])
"""
A signal that is sent before the userinfo token is returned to the openid client.
"""