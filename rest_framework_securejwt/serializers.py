from rest_framework import serializers


class RefreshSerializer(serializers.Serializer):
    refresh_token = serializers.CharField(allow_blank=False, allow_null=False)


class RegisterSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150, allow_blank=False, allow_null=False)
    email = serializers.EmailField(max_length=254, allow_blank=False, allow_null=False)
    password = serializers.CharField(min_length=6, max_length=128)


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(max_length=150, allow_blank=False, allow_null=False)
    password = serializers.CharField(min_length=6, max_length=128)
