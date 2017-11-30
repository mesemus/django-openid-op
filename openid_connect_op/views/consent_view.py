from django import forms
from django.views.generic import FormView

from openid_connect_op.models import OpenIDAgreement


class ConsentForm(forms.Form):
    def __init__(self, *args, user=None, client=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.agreements = list(client.get_user_agreements(user))
        self.agreed_agreements = set(OpenIDAgreement.objects.filter(client=client, user_agreements__user=user))
        for agreement in self.agreements:
            self.fields['agreement_%s' % agreement.id] = \
                forms.BooleanField(required=False,
                                   initial=agreement in self.agreed_agreements or agreement.obligatory,
                                   disabled=agreement.obligatory,
                                   label=agreement.text)

    def save(self):
        if not self.is_valid():
            raise ValueError('Can not save invalid data')


class ConsentView(FormView):
    template_name = 'django-open-id/consent.html'
    form_class = ConsentForm
