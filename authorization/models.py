from __future__ import unicode_literals

from django.contrib.auth.models import AbstractBaseUser
from django.db import models

from rest_framework_jwt.settings import api_settings

from authorization.managers import UserManager


class DatabaseCommonFields(models.Model):
    created_on = models.DateTimeField(auto_now=True, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True, null=True, blank=True)

    class Meta:
        abstract = True


class User(AbstractBaseUser):
    """
        model to store user infomation
    """
    first_name = models.CharField(
        max_length=50, null=True, blank=True)
    password = models.CharField(max_length=128)
    last_name = models.CharField(max_length=50, null=True, blank=True)
    email = models.EmailField(
        max_length=254, db_index=True, unique=True)
    username = models.CharField(
        max_length=30, unique=True, db_index=True)
    is_bakery_admin = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    last_login = models.DateTimeField(null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True, blank=True)

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['email', 'password']

    def get_jwt_token_for_user(self):
        """ get jwt token for the user """
        jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        payload = jwt_payload_handler(self)
        payload.update({
            "is_bakery_admin": self.is_bakery_admin,
            "first_name": self.first_name,
            "last_name": self.last_name,
        })
        token = jwt_encode_handler(payload)
        return token

    class Meta:
        def __str__(self):
            return self.get_full_name()
