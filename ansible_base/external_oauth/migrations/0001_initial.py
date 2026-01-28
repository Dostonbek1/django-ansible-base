# Generated manually for external_oauth app

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='ExternalOAuthProvider',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True, help_text='The date/time this resource was created.')),
                ('created_by', models.ForeignKey(
                    default=None,
                    editable=False,
                    help_text='The user who created this resource.',
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='%(app_label)s_%(class)s_created+',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('modified', models.DateTimeField(auto_now=True, help_text='The date/time this resource was created.')),
                ('modified_by', models.ForeignKey(
                    default=None,
                    editable=False,
                    help_text='The user who last modified this resource.',
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='%(app_label)s_%(class)s_modified+',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('name', models.CharField(help_text='A unique name for this provider configuration.', max_length=255, unique=True)),
                ('provider_type', models.CharField(
                    choices=[('entra_id', 'Azure AD / Entra ID'), ('oidc', 'Generic OIDC'), ('oauth2', 'Custom OAuth 2.0')],
                    default='oidc',
                    help_text='The type of OAuth provider.',
                    max_length=32,
                )),
                ('enabled', models.BooleanField(default=True, help_text='Whether this provider is enabled for token validation.')),
                ('issuer', models.URLField(help_text='The issuer URL (iss claim) for this provider. Used to match incoming tokens.', max_length=1024)),
                ('authorization_url', models.URLField(blank=True, help_text='Authorization endpoint URL (optional, for reference).', max_length=1024, null=True)),
                ('token_url', models.URLField(blank=True, help_text='Token endpoint URL (optional, for reference).', max_length=1024, null=True)),
                ('userinfo_url', models.URLField(blank=True, help_text='UserInfo endpoint URL for fetching additional user claims.', max_length=1024, null=True)),
                ('jwks_uri', models.URLField(blank=True, help_text='JWKS endpoint URL for retrieving public keys to validate JWT signatures.', max_length=1024, null=True)),
                ('introspection_url', models.URLField(blank=True, help_text='Token introspection endpoint URL for validating opaque tokens.', max_length=1024, null=True)),
                ('client_id', models.CharField(blank=True, help_text='Client ID for token introspection (if required by provider).', max_length=255, null=True)),
                ('client_secret', models.CharField(blank=True, help_text='Client secret for token introspection (stored encrypted).', max_length=1024, null=True)),
                ('expected_audience', models.CharField(blank=True, help_text='Expected audience (aud) claim. Comma-separated for multiple values.', max_length=1024, null=True)),
                ('jwt_algorithms', models.JSONField(blank=True, default=list, help_text='List of allowed JWT signing algorithms (e.g., ["RS256", "RS384"]).')),
                ('user_claim', models.CharField(default='email', help_text='The claim to use for mapping to AAP users (e.g., email, sub, preferred_username).', max_length=64)),
                ('client_id_claim', models.CharField(default='azp', help_text='The claim to use for identifying service principal/application tokens (e.g., azp, client_id).', max_length=64)),
                ('jwks_cache_timeout', models.IntegerField(default=3600, help_text='How long to cache JWKS keys (in seconds). Default: 1 hour.')),
                ('verify_ssl', models.BooleanField(default=True, help_text='Whether to verify SSL certificates when calling provider endpoints.')),
            ],
            options={
                'verbose_name': 'External OAuth Provider',
                'verbose_name_plural': 'External OAuth Providers',
                'ordering': ['name'],
            },
        ),
        migrations.CreateModel(
            name='ExternalApplication',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True, help_text='The date/time this resource was created.')),
                ('created_by', models.ForeignKey(
                    default=None,
                    editable=False,
                    help_text='The user who created this resource.',
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='%(app_label)s_%(class)s_created+',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('modified', models.DateTimeField(auto_now=True, help_text='The date/time this resource was created.')),
                ('modified_by', models.ForeignKey(
                    default=None,
                    editable=False,
                    help_text='The user who last modified this resource.',
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='%(app_label)s_%(class)s_modified+',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('name', models.CharField(help_text='A human-readable name for this external application.', max_length=255)),
                ('description', models.TextField(blank=True, help_text='A description of what this external application does.', null=True)),
                ('provider', models.ForeignKey(
                    help_text='The OAuth provider this application authenticates through.',
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='applications',
                    to='dab_external_oauth.externaloauthprovider',
                )),
                ('client_id', models.CharField(
                    help_text='The OAuth client ID from the external provider. This is used to match incoming tokens to this application.',
                    max_length=255,
                )),
                ('enabled', models.BooleanField(default=True, help_text='Whether this external application is allowed to authenticate.')),
                ('owner', models.ForeignKey(
                    blank=True,
                    help_text='Optional owner/administrator of this external application.',
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='owned_external_applications',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('last_used', models.DateTimeField(blank=True, help_text='When this external application last authenticated.', null=True)),
            ],
            options={
                'verbose_name': 'External Application',
                'verbose_name_plural': 'External Applications',
                'ordering': ['name'],
                'unique_together': {('provider', 'client_id')},
            },
        ),
        migrations.CreateModel(
            name='ExternalApplicationRoleAssignment',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created', models.DateTimeField(auto_now_add=True, help_text='The date/time this resource was created.')),
                ('created_by', models.ForeignKey(
                    default=None,
                    editable=False,
                    help_text='The user who created this resource.',
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='%(app_label)s_%(class)s_created+',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('modified', models.DateTimeField(auto_now=True, help_text='The date/time this resource was created.')),
                ('modified_by', models.ForeignKey(
                    default=None,
                    editable=False,
                    help_text='The user who last modified this resource.',
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    related_name='%(app_label)s_%(class)s_modified+',
                    to=settings.AUTH_USER_MODEL,
                )),
                ('application', models.ForeignKey(
                    help_text='The external application receiving the role.',
                    on_delete=django.db.models.deletion.CASCADE,
                    related_name='role_assignments',
                    to='dab_external_oauth.externalapplication',
                )),
                ('role_definition', models.CharField(
                    help_text='The role definition to assign (e.g., "Organization Admin", "Team Member").',
                    max_length=255,
                )),
                ('content_type', models.CharField(blank=True, help_text='Optional content type to scope the role (e.g., "organization", "team").', max_length=255, null=True)),
                ('object_id', models.PositiveIntegerField(blank=True, help_text='Optional object ID to scope the role.', null=True)),
            ],
            options={
                'verbose_name': 'External Application Role Assignment',
                'verbose_name_plural': 'External Application Role Assignments',
                'unique_together': {('application', 'role_definition')},
            },
        ),
    ]
