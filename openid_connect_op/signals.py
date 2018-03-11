import django.dispatch

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
