from django.contrib.auth.base_user import BaseUserManager

import authorization.mixins as accounts_mixin


class UserManager(BaseUserManager,
                  accounts_mixin.AccountQueryMixin):

    def _create_user(self, email, password, is_bakery_admin=None, **extra_fields):
        """
            Creates and saves a User with the given email and password.
        """
        try:
            if not email:
                raise ValueError('The given email must be set')
            email = self.normalize_email(email)
            if is_bakery_admin:
                user = self.model(
                    email=email, is_bakery_admin=True, **extra_fields
                )
            else:
                user = self.model(
                    email=email, **extra_fields
                )
            user.set_password(password)
            user.save(using=self._db)
        except Exception as e:
            return e
        return user

    def create_bakery_admin(self, email, password=None, **extra_fields):
        is_bakery_admin = True
        return self._create_user(email, password, is_bakery_admin, **extra_fields)
