from django.contrib.auth.base_user import BaseUserManager
from django.db import models

import authorization.mixins as accounts_mixin


class UserManager(BaseUserManager,
                  accounts_mixin.AccountQueryMixin):

    def _create_user(self, email, password, client=None, **extra_fields):
        """
            Creates and saves a User with the given email and password.
        """
        try:
            if not email:
                raise ValueError('The given email must be set')
            email = self.normalize_email(email)
            if client:
                user = self.model(
                    email=email, is_client=True,
                    has_access_mobile_dashboard=True,
                    has_access_web_dashboard=True, **extra_fields
                )
            else:
                user = self.model(
                    email=email, is_superadmin=True,
                    has_access_mobile_dashboard=True,
                    has_access_web_dashboard=True,
                    **extra_fields
                )
            user.set_password(password)
            user.full_clean(exclude=['phone_number', ])
            user.save(using=self._db)
        except Exception as e:
            return e
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        return self._create_user(email, password, **extra_fields)

    def create_client(self, email, password=None, **extra_fields):
        client = True
        return self._create_user(email, password, client, **extra_fields)


class UserOtpManager(models.Manager, accounts_mixin.UserOtpQueryMixin):
    """ custom UserOtp manager """

    def get_queryset(self):
        return accounts_mixin.UserOtpQuerySet(self.model, using=self._db)


class RoleManager(models.Manager):
    """
        The manager for the auth's role model.
    """
    use_in_migrations = True

    def get_by_natural_key(self, role_name):
        return self.get(role_name=role_name)

    def filter_role_by_site_id(self, site_id):
        return self.filter(site_id=site_id)
