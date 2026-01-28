from django.apps import AppConfig


class ExternalOAuthConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'ansible_base.external_oauth'
    label = 'dab_external_oauth'
    verbose_name = 'External OAuth Authentication'
