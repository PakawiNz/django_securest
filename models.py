from secrets import token_hex

from django.contrib.auth.models import User
from django.db import models
from django.utils.crypto import get_random_string

API_KEY_LENGTH = 64
SECRET_KEY_LENGTH = 64


class SecurestToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='+')
    name = models.CharField(max_length=255)
    api_key = models.CharField(max_length=API_KEY_LENGTH, editable=False)
    secret_key = models.CharField(max_length=SECRET_KEY_LENGTH, editable=False)
    created = models.DateTimeField(auto_now_add=True, editable=False)
    updated = models.DateTimeField(auto_now=True, editable=False)
    last_used = models.DateTimeField(null=True, blank=True, editable=False)

    objects = models.QuerySet.as_manager()

    def clean(self):
        if not self.pk:
            self.api_key = token_hex(int(API_KEY_LENGTH / 2))
            self.secret_key = get_random_string(length=SECRET_KEY_LENGTH)

    def __str__(self):
        return self.name
