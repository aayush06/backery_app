from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from rest_framework import serializers

from helpers.serializers_fields import (CustomEmailSerializerField)
from authorization.models import User
from authorization.utils import messages, custom_validators as valid


class LoginSerializer(serializers.Serializer):
    """
       serializer for login view
    """
    username = serializers.CharField()
    password = serializers.CharField()

    default_error_messages = {
        'inactive_account': messages.INACTIVE_ACCOUNT_ERROR,
        'invalid_credentials': messages.INVALID_CREDENTIALS_ERROR,
        'invalid_account': messages.NON_REGISTERED_ACCOUNT,
        'no_access_for_mobile': messages.NO_MOBILE_ACCESS,
        'no_access_for_web': messages.NO_WEB_ACCESS,
        'device_not_registered': messages.DEVICE_NOT_REGISTERED
    }

    def __init__(self, *args, **kwargs):
        super(LoginSerializer, self).__init__(*args, **kwargs)
        self.user = None

    def validate(self, attrs):
        try:
            user = User.objects.get_user_by_username(attrs['username'])
        except User.DoesNotExist:
            raise serializers.ValidationError(
                self.error_messages['invalid_account']
            )
        if user and not user.is_active:
            raise serializers.ValidationError(
                self.error_messages['inactive_account']
            )
        self.user = authenticate(username=attrs.get(User.USERNAME_FIELD),
                                 password=attrs.get('password'))
        if not self.user:
            raise serializers.ValidationError(
                self.error_messages['invalid_credentials'])
        return attrs


class RegistrationSerializer(serializers.ModelSerializer):
    """
        serializer for registering new user
    """
    password = serializers.CharField(write_only=True, min_length=6, style={
        'input_type': 'password'},
                                     validators=[
                                         valid.validate_password_field
                                     ])
    email = CustomEmailSerializerField()
    username = serializers.CharField(
        min_length=6,
        max_length=30,
        required=True
    )
    first_name = serializers.CharField(
        min_length=2,
        max_length=50,
        required=True)
    last_name = serializers.CharField(
        min_length=2,
        max_length=50,
        required=False,
        allow_null=True,
        allow_blank=True)

    def validate_username(self, username):
        if User.objects.filter(username=username):
            raise serializers.ValidationError(
                messages.USERNAME_ALREADY_EXISTS
            )
        return username

    def validate_email(self, email):
        if User.objects.filter(email=email):
            raise serializers.ValidationError(
                messages.EMAIL_ALREADY_EXITS
            )
        return email

    class Meta:
        model = User
        fields = (
            'username', 'email', 'last_name',
            'password', 'id', 'first_name'
        )
        extra_kwargs = {
                        'username': {'required': True}
                        }


class BackeryAdminRegistrationSerializer(serializers.ModelSerializer):
    """
        serializer for registering admin
    """
    password = serializers.CharField(write_only=True, min_length=6, style={
        'input_type': 'password'},
                                     validators=[
                                         valid.validate_password_field
                                     ])
    email = CustomEmailSerializerField()
    username = serializers.CharField(
        min_length=6,
        max_length=30,
        required=True
    )
    first_name = serializers.CharField(
        min_length=2,
        max_length=50,
        required=True)
    last_name = serializers.CharField(
        min_length=2,
        max_length=50,
        required=False,
        allow_null=True,
        allow_blank=True)

    def validate_username(self, username):
        if User.objects.filter(username=username):
            raise serializers.ValidationError(
                messages.USERNAME_ALREADY_EXISTS
            )
        return username

    def validate_email(self, email):
        if User.objects.filter(email=email):
            raise serializers.ValidationError(
                messages.EMAIL_ALREADY_EXITS
            )
        return email

    class Meta:
        model = User
        fields = (
            'username', 'email', 'last_name',
            'password', 'id', 'first_name'
        )
        extra_kwargs = {
                        'username': {'required': True}
                        }

    def create(self, validated_data):
        user = User.objects.create_bakery_admin(**validated_data)
        try:
            user.save()
            return user
        except (ValidationError, AssertionError, AttributeError):
            raise serializers.ValidationError(user)
