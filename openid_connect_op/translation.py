from modeltranslation.translator import translator, TranslationOptions
from .models import OpenIDClient, OpenIDAgreement


class OpenIDClientTranslationOptions(TranslationOptions):
    fields = ('client_name',)


class OpenIDAgreementTranslationOptions(TranslationOptions):
    fields = ('text',)


translator.register(OpenIDClient, OpenIDClientTranslationOptions)
translator.register(OpenIDAgreement, OpenIDAgreementTranslationOptions)
