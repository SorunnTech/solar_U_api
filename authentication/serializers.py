from rest_framework import serializers
from authentication.models import CustomUser
from roles.serializers import RoleSerializer


class UserSerializer(serializers.ModelSerializer):
    role = RoleSerializer()

    class Meta:
        model = CustomUser
        fields = ['id', 'username', 'first_name', 'last_name', 'email',
                  'phone_number', 'role', 'is_active', 'last_login', 'date_joined']


class LoginSerializer(UserSerializer):
    class Meta(UserSerializer.Meta):
        fields = ['phone_number', 'password']


class RegisterSerializer(UserSerializer):
    class Meta(UserSerializer.Meta):
        fields = ['first_name', 'last_name', 'email',
                  'phone_number', 'role', 'password']
