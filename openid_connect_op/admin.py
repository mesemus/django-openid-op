from django.contrib import admin
from modeltranslation.admin import TranslationAdmin, TranslationStackedInline

from openid_connect_op.models import OpenIDClient, OpenIDAgreement


class OpenIDAgreementAdmin(TranslationStackedInline):
    model = OpenIDAgreement


class OpenIDClientAdmin(TranslationAdmin):
    inlines = (OpenIDAgreementAdmin, )


admin.site.register(OpenIDClient, OpenIDClientAdmin)