import re
import os

from django.core.exceptions import ValidationError
from rest_framework import serializers


def validate_password_field(value):
    """
        method to check validity of password field
    """
    msg = []
    if len(value) < 6:
        msg.append("password must be 6 characters or longer")
    if len(msg) > 0:
        raise serializers.ValidationError(msg)


def validate_char_field(value):
    """
        method to check validity of char field
    """
    msg = []
    if value:
        if re.search("[0-9]", value):
            msg.append("field must not contain any numeric digit")
        if not value.isalnum() and re.search("[!@#$%^&*()_+=~`<>,{.?/;:}-]",value):
            msg.append("field must not contain any special character")
        if len(msg) > 0:
            raise serializers.ValidationError(msg)


def validate_username_field(value):
    """
        method to check validity of username field
    """
    msg = []
    if value:
        if not value.isalnum() and "_" not in value:
            msg.append(
                "field mustn't contain any special character other than _")
        if not ((re.search("[a-z]", value))or(re.search("[A-Z]", value))):
            msg.append("field must contain atleast one character")
        if len(msg) > 0:
            raise serializers.ValidationError(msg)
