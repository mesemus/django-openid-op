from django.views import View
from django.views.generic import TemplateView


class ConsentView(View):
    pass


class IndexView(TemplateView):
    template_name = 'index.html'