from django.contrib import admin
from modeltranslation.admin import TranslationAdmin, TranslationStackedInline

from openid_connect_op.models import OpenIDClient, OpenIDAgreement, OpenIDUserAgreement


class OpenIDAgreementAdmin(TranslationStackedInline):
    model = OpenIDAgreement


class OpenIDClientAdmin(TranslationAdmin):
    inlines = (OpenIDAgreementAdmin, )

class OpenIDUserAgreementAdmin(admin.ModelAdmin):
    list_display = ('agreement__client', 'user', 'agreement_obligatory', 'agreement_text')
    list_filter = ('agreement__client__client_name', )
    search_fields = ('user__username', 'user__last_name')
    readonly_fields = ('agreement', 'user', 'agreed_on', 'agreed_by_user')

    def agreement__client(self, instance):
        return instance.agreement.client

    def user(self, instance):
        return instance.user.get_full_name()

    def agreement_obligatory(self, instance):
        return instance.agreement.obligatory

    def agreement_text(self, instance):
        return instance.agreement.text[:50]

admin.site.register(OpenIDClient, OpenIDClientAdmin)
admin.site.register(OpenIDUserAgreement, OpenIDUserAgreementAdmin)