from rest_framework import serializers
from roles.models import user_roles
class RoleSerializer(serializers.ModelSerializer):
    class Meta:
        model = user_roles
        fields = ['id', 'role_name', 'role_description', 'date_added']


class AddRoleSerializer(RoleSerializer):
    class Meta(RoleSerializer.Meta):
        fields=['role_name','role_description']