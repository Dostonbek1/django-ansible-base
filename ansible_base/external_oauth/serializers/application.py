"""
Serializers for External Application management.
"""
from rest_framework import serializers

from ansible_base.external_oauth.models import ExternalApplication, ExternalApplicationRoleAssignment


class ExternalApplicationRoleAssignmentSerializer(serializers.ModelSerializer):
    """Serializer for External Application Role Assignments."""
    
    class Meta:
        model = ExternalApplicationRoleAssignment
        fields = [
            'id',
            'application',
            'role_definition',
            'content_type',
            'object_id',
            'created',
            'modified',
        ]
        read_only_fields = ['id', 'created', 'modified']


class ExternalApplicationSerializer(serializers.ModelSerializer):
    """
    Serializer for ExternalApplication model.
    """
    
    provider_name = serializers.CharField(source='provider.name', read_only=True)
    role_assignments = ExternalApplicationRoleAssignmentSerializer(many=True, read_only=True)
    
    class Meta:
        model = ExternalApplication
        fields = [
            'id',
            'name',
            'description',
            'provider',
            'provider_name',
            'client_id',
            'enabled',
            'owner',
            'last_used',
            'role_assignments',
            'created',
            'modified',
        ]
        read_only_fields = ['id', 'last_used', 'created', 'modified']
    
    def validate(self, attrs):
        """Validate that the client_id is unique per provider."""
        provider = attrs.get('provider') or (self.instance and self.instance.provider)
        client_id = attrs.get('client_id') or (self.instance and self.instance.client_id)
        
        if provider and client_id:
            existing = ExternalApplication.objects.filter(
                provider=provider,
                client_id=client_id
            )
            if self.instance:
                existing = existing.exclude(pk=self.instance.pk)
            
            if existing.exists():
                raise serializers.ValidationError(
                    f"An application with client_id '{client_id}' already exists "
                    f"for provider '{provider.name}'"
                )
        
        return attrs


class ExternalApplicationListSerializer(serializers.ModelSerializer):
    """
    Simplified serializer for listing applications.
    """
    
    provider_name = serializers.CharField(source='provider.name', read_only=True)
    role_count = serializers.SerializerMethodField()
    
    class Meta:
        model = ExternalApplication
        fields = [
            'id',
            'name',
            'provider',
            'provider_name',
            'client_id',
            'enabled',
            'last_used',
            'role_count',
            'created',
            'modified',
        ]
    
    def get_role_count(self, obj):
        return obj.role_assignments.count()
