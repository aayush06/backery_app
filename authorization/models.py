from __future__ import unicode_literals

import random
import json
from django.utils.translation import ugettext_lazy as _

from django.contrib.auth.models import AbstractBaseUser
from django.contrib.postgres.fields import JSONField
from django.db import models

from phonenumber_field.modelfields import PhoneNumberField
from rest_framework_jwt.settings import api_settings

from authorization.managers import UserManager, UserOtpManager, RoleManager
from authorization.utils.custom_validators import validate_file_extension
from authorization.utils.choices import (permission_choices,
                                         start_page_choices)
from helpers.requests_handler import ConfigurationRequestHandler
import phonenumbers
from phonenumbers.phonenumberutil import region_code_for_number, \
    PhoneMetadata, national_significant_number
from phonenumber_field.phonenumber import PhoneNumber
from django.conf import settings

conf_request_handler = ConfigurationRequestHandler()


def custom_is_valid_number_for_region(numobj, region_code):
    country_code = numobj.country_code
    if region_code is None:
        return False
    metadata = PhoneMetadata.metadata_for_region_or_calling_code(country_code, region_code.upper())
    nsn = national_significant_number(numobj)
    return True


class CustomPhoneNumberAttr(PhoneNumber):
    format_map = {
        "E164": phonenumbers.PhoneNumberFormat.E164,
        "INTERNATIONAL": phonenumbers.PhoneNumberFormat.INTERNATIONAL,
        "NATIONAL": phonenumbers.PhoneNumberFormat.NATIONAL,
        "RFC3966": phonenumbers.PhoneNumberFormat.RFC3966,
        "NO_VAL": 4
        # All the other formats are having sequential values from 0 to 3
    }

    @classmethod
    def from_string(cls, phone_number, region=None):
        phone_number_obj = cls()
        if region is None:
            region = getattr(settings, "PHONENUMBER_DEFAULT_REGION", None)
        phonenumbers.parse(
            number=phone_number,
            region=region,
            keep_raw_input=True,
            numobj=phone_number_obj,
        )
        return phone_number_obj

    def __str__(self):
        format_string = getattr(settings, "PHONENUMBER_DEFAULT_FORMAT", "E164")
        fmt = self.format_map[format_string]
        return self.format_as(fmt)

    def is_valid(self):
        region_code = region_code_for_number(self)
        return custom_is_valid_number_for_region(self, region_code)

    def format_as(self, format):
        return phonenumbers.format_number(self, format)

    def __len__(self):
        return len(str(self))

    def __eq__(self, other):
        if isinstance(other, (str, phonenumbers.PhoneNumber)):
            format_string = getattr(settings, "PHONENUMBER_DB_FORMAT", "E164")
            default_region = getattr(settings, "PHONENUMBER_DEFAULT_REGION", None)
            fmt = self.format_map[format_string]
            if isinstance(other, str):
                try:
                    other = phonenumbers.parse(other, region=default_region)
                except phonenumbers.NumberParseException:
                    return False
            other_string = phonenumbers.format_number(other, fmt)
            return self.format_as(fmt) == other_string
        else:
            return False

    def __hash__(self):
        return hash(str(self))


class CustomPhoneNumberField(PhoneNumberField):
    attr_class = CustomPhoneNumberAttr

    def get_prep_value(self, value):
        if isinstance(value, PhoneNumber):
            setattr(value, "format_map", CustomPhoneNumberAttr.format_map)
        if value:
            from helpers.serializers_fields import to_python as custom_to_python
            if isinstance(value, PhoneNumber):
                value = custom_to_python(value)

            if not value.is_valid():
                raise ValueError("“%s” is not a valid phone number." % value.raw_input)

            format_string = getattr(settings, "PHONENUMBER_DB_FORMAT", "E164")
            fmt = CustomPhoneNumberAttr.format_map[format_string]
            value = value.format_as(fmt)
        return value


class DatabaseCommonFields(models.Model):
    updated_on = models.DateTimeField(auto_now=True, null=True, blank=True)
    site_id = models.PositiveIntegerField(
        null=True, blank=True
    )

    class Meta:
        abstract = True


class Permission(models.Model):
    """
    model to store permissions
    """
    permission_name = models.CharField(
        choices=permission_choices, max_length=50, unique=True
    )
    description = models.CharField(
        max_length=100, null=True, blank=True
    )
    created_on = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    updated_on = models.DateTimeField(auto_now=True, null=True, blank=True)


class Role(DatabaseCommonFields):
    """
    model to store role information
    """
    role_name = models.CharField(
        max_length=30, db_index=True)
    role_importance = models.IntegerField()
    permissions = models.ManyToManyField(
        Permission, blank=True, related_name="permissions")
    is_active = models.BooleanField(default=True)
    created_on = models.DateTimeField(auto_now_add=True, null=True, blank=True)

    objects = RoleManager()

    def get_role_permissions(self):
        """ return list of all permission related to the role """
        if self.permissions:
            return [i.permission_name for i in self.permissions.all()]

    def get_role_permission_with_description(self):
        """ return all permission with its description related to the role """
        if self.permissions:
            return [{
                "id": i.id,
                "permission_name": i.permission_name,
                "description": i.description} for i in self.permissions.all()]

    def get_role_importance(self):
        """ return role importance """
        return self.role_importance

    def add_permissions(self, permission_id):
        """add permissions to role"""
        permission_obj = Permission.objects.get(id=permission_id)
        self.permissions.add(permission_obj)

    def set_role_status(self, status):
        """modify status of role"""
        self.is_active = status

    def set_role_active(self):
        """ make role active """
        self.is_active = True

    def set_role_inactive(self):
        """ make role inactive """
        self.is_active = False

    class Meta:
        unique_together = ('role_name', 'site_id',)

        def __str__(self):
            return self.role_name


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
    phone_number = CustomPhoneNumberField(blank=True, null=True)
    username = models.CharField(
        max_length=30, unique=True, db_index=True)
    profile_pic = models.ImageField(
        upload_to="media/profile/", null=True,
        blank=True, validators=[validate_file_extension])
    role = models.ForeignKey(
        "authorization.role", related_name="user_role",
        on_delete=models.DO_NOTHING, null=True, blank=True
    )
    account_id = models.PositiveIntegerField(
        null=True, blank=True
    )
    start_page = models.CharField(
        choices=start_page_choices, max_length=50,
        null=True, blank=True
    )
    poi_id = models.PositiveIntegerField(
        null=True, blank=True
    )
    license_number = models.CharField(
        max_length=50, null=True, blank=True
    )
    imei_number = models.CharField(
        max_length=50, null=True, blank=True
    )
    package_id = models.PositiveIntegerField(
        null=True, blank=True
    )
    subscription_date = models.DateTimeField(null=True, blank=True)
    package_payment_success = models.BooleanField(null=True, blank=True)
    no_of_employees = models.PositiveIntegerField(
        null=True, blank=True
    )
    renewal_date = models.DateField(null=True, blank=True)
    is_superadmin = models.BooleanField(default=False)
    is_client = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    has_access_mobile_dashboard = models.BooleanField(default=False)
    has_access_web_dashboard = models.BooleanField(default=False)
    last_login = models.DateTimeField(null=True, blank=True)
    team = models.ManyToManyField(
        "team.Team", blank=True,
        related_name="team_member")
    created_on = models.DateTimeField(auto_now_add=True, null=True, blank=True)
    site_id = models.PositiveIntegerField(
        null=True, blank=True
    )
    address = models.CharField(
        max_length=100, null=True, blank=True
    )
    city = models.CharField(
        max_length=30, null=True, blank=True
    )
    state = models.CharField(
        max_length=30, null=True, blank=True
    )
    country = models.CharField(
        max_length=30, null=True, blank=True
    )
    pin_code = models.CharField(
        max_length=10, null=True, blank=True
    )
    employee_id = models.CharField(
        max_length=30, null=True, blank=True)
    off_days = JSONField(default=dict, null=True, blank=True)
    hidden_on_scheduler = models.BooleanField(default=False)
    linking_id = models.TextField(
        null=True, blank=True
    )

    objects = UserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['phone_number', 'email', 'password']

    def get_full_name(self):
        """
            Returns the first_name plus the last_name, with a space in between.
        """
        return self.first_name + ' ' + self.last_name

    def get_short_name(self):
        """
            Returns the short name for the user.
        """
        return self.first_name

    def get_email(self):
        """returns email id of user"""
        return self.email

    def get_phone_number(self):
        """return the user Phone number """
        return self.phone_number

    def is_user_active(self):
        """ check check user is active """
        return self.is_active

    def set_active(self):
        """set a user active"""
        self.is_active = True

    def set_inactive(self):
        """set a user inactive"""

        self.is_active = False

    def get_user_id(self):
        """ return the user id"""
        return self.id

    def get_permissions_of_user(self):
        """ return permissions of user """
        if self.role and self.role.role_name.lower() == "supervisor":
            return []
        if self.role:
            return self.role.get_role_permissions()
        return []

    def user_has_permission(self, permission):
        """check whether user has particular permission"""
        if self.role:
            return permission in self.get_permissions_of_user()

    def get_jwt_token_for_user(self):
        """ get jwt token for the user """
        jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
        jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
        payload = jwt_payload_handler(self)
        enable_work_chat = None
        account_timezone = None
        if self.account_id:
            account_obj = conf_request_handler.get_account_details(
                self.account_id, self.site_id)
            if account_obj:
                enable_work_chat = account_obj['work_chat']
                account_timezone = account_obj['time_zone']
        else:
            if self.role and self.role.role_name.lower() in ["client", "superadmin"]:
                enable_work_chat = True
        permissions = []
        payload.update({
            "is_superadmin": self.is_superadmin,
            "account_id": self.account_id,
            "enable_work_chat": enable_work_chat,
            "permission": permissions,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "account_timezone": account_timezone,
            "linking_id": self.linking_id,
            "site_id": self.site_id
        })

        if self.role:
            permissions = self.role.get_role_permissions()
            payload.update({
                "permission": permissions,
                "role_name": self.role.role_name,
                "role_id": self.role.id
            })
        token = jwt_encode_handler(payload)
        return token, permissions, account_timezone

    def generate_otp(self, email, phone_number=None):

        otp_code = random.randint(11111, 99999)
        data = {
            'user': self,
            'otp': otp_code
        }
        try:
            user_otp = UserOtp.objects.get_otp_of_user(self)
            user_otp.delete()
            user_otp = UserOtp.objects.create(**data)
        except UserOtp.DoesNotExist:
            user_otp = UserOtp.objects.create(**data)

        return user_otp.get_otp()

    def generate_otp_send(self, phone_number=None, msg_template=None):
        """
            :param phone_number: Phone number on which otp have to send
            :return:
        """

        otp_code = random.randint(11111, 99999)
        data = {
            'user': self,
            'otp': otp_code
        }
        try:
            user_otp = UserOtp.objects.get_otp_of_user(self)
            user_otp.delete()
            user_otp = UserOtp.objects.create(**data)
        except UserOtp.DoesNotExist:
            user_otp = UserOtp.objects.create(**data)
        context = dict()
        context['otp'] = otp_code
        return user_otp.get_otp()

    def save(self, *args, **kwargs):
        super(User, self).save(*args, **kwargs)
        from helpers.tasks import cache_data_users
        from authorization.serializers import UserListSerializer

        del_key = f"{self.__class__.__name__}_{self.id}"
        team_info = "_".join([str(team_id) for team_id in self.team.values_list('id', flat=True)])
        redis_key = f"{self.__class__.__name__}_{self.id}_{self.account_id if self.account_id else 0}_{team_info}"
        redis_value = json.dumps(UserListSerializer(self).data)
        print("save called")
        cache_data_users.delay(redis_key, redis_value, del_key)

    class Meta:
        def __str__(self):
            return self.get_full_name()


class UserOtp(models.Model):
    """ model for user otp"""

    user = models.OneToOneField(User, on_delete=models.CASCADE)
    otp = models.CharField(max_length=5)
    created_on = models.DateTimeField(auto_now_add=True, null=True, blank=True)

    objects = UserOtpManager()

    def __str__(self):
        return "{0}-{1}".format(self.user.email, self.otp)

    def get_user(self):
        return self.user

    def get_otp(self):
        return self.otp

    def get_created_time(self):
        return self.created_on


class UserAlertPreferences(DatabaseCommonFields):
    """ model for user alert prefernces """
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    clock_in_out_alert_mode = JSONField(null=True, blank=True)
    overtime_alert_mode = JSONField(null=True, blank=True)
    shift_alert_mode = JSONField(null=True, blank=True)
    hours_before_shift_alert = models.PositiveIntegerField(
        null=True, blank=True)
    created_on = models.DateTimeField(auto_now_add=True)


class UserSiteManager(models.Model):
    """
        models to store user and site mapping
    """
    site_manager = models.OneToOneField(
        User, on_delete=models.CASCADE)


class RequestedDownload(models.Model):
    Initiated = "initiated"
    In_progress = "in_progress"
    Completed = "completed"

    requested_by = models.EmailField(null=True, blank=True)
    requested_on = models.DateTimeField(auto_now_add=True)
    file_path = models.URLField(null=True, blank=True)
    task_id = models.CharField(
        max_length=255, null=True, blank=True, default=None)

    STATUS = (
        (Initiated, _("initiated")),
        (In_progress, _("in_progress")),
        (Completed, _("completed"))
    )

    status = models.CharField(
        default=Initiated, choices=STATUS, max_length=20)

    requested_filter = models.TextField(null=True, blank=True)


class SingletonModel(models.Model):
    """Singleton Django Model"""

    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        """
        Save object to the database. Removes all other entries if there
        are any.
        """
        self.__class__.objects.exclude(id=self.id).delete()
        super(SingletonModel, self).save(*args, **kwargs)

    @classmethod
    def load(cls):
        """
        Load object from the database. Failing that, create a new empty
        (default) instance of the object and return it (without saving it
        to the database).
        """

        try:
            return cls.objects.get()
        except cls.DoesNotExist:
            return cls()


class AppVersion(SingletonModel):
    app_version = JSONField(default=dict())


class ThrottlingModel(models.Model):
    user_id = models.PositiveIntegerField(
        null=True, blank=True)
    consumed_request_count = models.PositiveIntegerField(
        null=True, blank=True, default=0
    )
    executed_on = models.DateTimeField(null=True, blank=True)
