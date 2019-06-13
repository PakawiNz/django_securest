import os

from django.apps import AppConfig

API_KEY_LENGTH = 64
SECRET_KEY_LENGTH = 64

class DjangoSecurestConfig(AppConfig):
    name = os.path.relpath(os.path.dirname(__file__), os.getcwd()).replace(os.path.sep, '.')
    verbose_name = "Django Securest"
