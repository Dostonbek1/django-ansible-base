"""
Serializers for External OAuth Provider management.
"""
from rest_framework import serializers

from ansible_base.external_oauth.models import ExternalOAuthProvider


class ExternalOAuthProviderSerializer(serializers.ModelSerializer):
    """
    Serializer for ExternalOAuthProvider model.
    
    Note: client_secret is write-only for security.
    """
    
    class Meta:
        model = ExternalOAuthProvider
        fields = [
            'id',
            'name',
            'provider_type',
            'enabled',
            'issuer',
            'authorization_url',
            'token_url',
            'userinfo_url',
            'jwks_uri',
            'introspection_url',
            'client_id',
            'client_secret',
            'expected_audience',
            'jwt_algorithms',
            'user_claim',
            'client_id_claim',
            'jwks_cache_timeout',
            'verify_ssl',
            'created',
            'modified',
        ]
        read_only_fields = ['id', 'created', 'modified']
        extra_kwargs = {
            'client_secret': {'write_only': True},
        }
    
    def validate_jwt_algorithms(self, value):
        """Validate JWT algorithms are supported."""
        from jwt.algorithms import get_default_algorithms
        supported = set(get_default_algorithms().keys())
        
        if value:
            invalid = set(value) - supported
            if invalid:
                raise serializers.ValidationError(
                    f"Unsupported JWT algorithms: {', '.join(invalid)}"
                )
        return value
    
    def validate(self, attrs):
        """Validate that required endpoints are configured based on provider type."""
        # At least one validation method must be configured
        jwks_uri = attrs.get('jwks_uri') or (self.instance and self.instance.jwks_uri)
        introspection_url = attrs.get('introspection_url') or (
            self.instance and self.instance.introspection_url
        )
        
        if not jwks_uri and not introspection_url:
            raise serializers.ValidationError(
                "Either jwks_uri or introspection_url must be configured"
            )
        
        return attrs


class ExternalOAuthProviderListSerializer(serializers.ModelSerializer):
    """
    Simplified serializer for listing providers (excludes sensitive fields).
    """
    
    application_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ExternalOAuthProvider
        fields = [
            'id',
            'name',
            'provider_type',
            'enabled',
            'issuer',
            'application_count',
            'created',
            'modified',
        ]
    
    def get_application_count(self, obj):
        return obj.applications.count()
