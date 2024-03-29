from django.contrib import admin

from .models import SecurestToken

admin.site.register(
    SecurestToken,
    list_display=['user', 'name', 'api_key'],
    readonly_fields=['api_key', 'secret_key', 'created', 'updated', 'last_used']
)
