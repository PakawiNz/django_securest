import os

from django.apps import AppConfig


class DjangoSecurestConfig(AppConfig):
    name = os.path.relpath(os.path.dirname(__file__), os.getcwd()).replace(os.path.sep, '.')
    verbose_name = "Django Securest"
