from django import forms
from django.http import HttpResponse
from django.utils import timezone
from django.utils.functional import cached_property
from django.views.generic import FormView

from openid_connect_op.models import OpenIDAgreement, OpenIDClient, OpenIDUserAgreement
from openid_connect_op.signals import after_user_consent


class ConsentForm(forms.Form):
    def __init__(self, *args, user=None, client=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.user = user
        self.agreements = list(client.get_user_agreements(user))
        self.agreed_agreements = set(OpenIDAgreement.objects.filter(client=client, user_agreements__user=user))
        for agreement in self.agreements:
            self.fields[self.agreement_field_name(agreement)] = \
                forms.BooleanField(required=False,
                                   label=agreement.text)
            agreement.agreed = agreement in self.agreed_agreements

    def agreement_field_name(self, agreement):
        return 'agreement_%s' % agreement.id

    def save(self):
        if not self.is_valid():
            raise ValueError('Can not save invalid data')
        for agreement in self.agreements:
            field_name = self.agreement_field_name(agreement)
            if agreement.obligatory or field_name in self.cleaned_data and self.cleaned_data[field_name]:
                # add the agreement if it does not exist
                OpenIDUserAgreement.objects.get_or_create(agreement=agreement, user=self.user, defaults={
                    'agreed_on': timezone.now(),
                    'agreed_by_user': True
                })
            else:
                # remove the agreement
                OpenIDUserAgreement.objects.filter(agreement=agreement, user=self.user).delete()


class ConsentView(FormView):
    template_name = 'django-open-id/consent.html'
    form_class = ConsentForm

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs['user'] = self.request.user
        kwargs['client'] = self.openid_client
        return kwargs

    @cached_property
    def openid_client(self):
        return OpenIDClient.objects.get(pk=self.kwargs['client_id'])

    def get_context_data(self, **kwargs):
        return super().get_context_data(client=self.openid_client, **kwargs)

    def form_valid(self, form):
        form.save()
        signal_responses = after_user_consent.send(type(self.openid_client),
                                openid_client=self.openid_client,
                                user=self.request.user)
        for resp in signal_responses:
            if isinstance(resp[1], HttpResponse):
                return resp[1]
        return super().form_valid(form)

    def get_success_url(self):
        return self.request.GET.get('next') or '/'
