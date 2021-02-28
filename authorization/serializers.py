import django.contrib.auth.password_validation as validators
from django.conf import settings
from django.contrib.auth import authenticate
from django.core.exceptions import ValidationError
from django.utils import timezone
import re
from rest_framework import exceptions, serializers

from helpers.serializers_fields import (CustomEmailSerializerField,
                                        PhoneNumberField)
from authorization.models import Permission, Role, User, UserOtp, RequestedDownload, AppVersion, ThrottlingModel
from authorization.utils import messages, custom_validators as valid
from authorization.utils.choices import permission_choices
from helpers.requests_handler import ConfigurationRequestHandler
from team.models import Team

conf_req_handler = ConfigurationRequestHandler()


class PermissionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Permission
        fields = ("id", "permission_name", "description", "created_on")
        swagger_schema_fields = {
            'example': {
                'permission_name': [i[0] for i in permission_choices],
                'description': 'example description'
            }}


class RoleDetailSerializer(serializers.ModelSerializer):
    role_name = serializers.CharField(max_length=30)
    permissions = serializers.SerializerMethodField()
    no_of_active_members = serializers.SerializerMethodField()

    def get_permissions(self, obj):
        return obj.get_role_permission_with_description()

    def get_no_of_active_members(self, obj):
        user_qs = User.objects.filter(role=obj, is_active=True)
        return len(user_qs)

    class Meta:
        model = Role
        fields = (
            "id", "role_name", "permissions",
            "role_importance",
            "is_active", "no_of_active_members", "created_on")
        read_only_fields = fields


class RoleSerializer(serializers.ModelSerializer):
    role_name = serializers.CharField(max_length=30)
    no_of_active_members = serializers.SerializerMethodField()

    def get_no_of_active_members(self, obj):
        if self.context['request'].site_id.lower() != 'system':
            user_qs = User.objects.filter(
                role=obj, is_active=True,
                site_id=self.context['request'].site_id)
            return len(user_qs)
        else:
            return 0

    class Meta:
        model = Role
        fields = (
            "id", "role_name", "is_active", "role_importance",
            "no_of_active_members", "created_on", "site_id")
        read_only_fields = fields


class RoleCreateUpdateSerializer(serializers.ModelSerializer):
    role_name = serializers.CharField(
        min_length=2,
        max_length=30,
        required=True
    )

    role_importance = serializers.IntegerField(
        min_value=0,
        max_value=10,
        required=True
    )

    def validate_role_name(self, role_name):
        if role_name.lower() in ['client', 'superadmin', 'driver', 'openapi']:
            raise serializers.ValidationError(
                messages.ROLE_NAME_NOT_ALLOWED
            )
        site_id = self.context['request'].site_id
        if Role.objects.filter(role_name=role_name, site_id=site_id):
            raise serializers.ValidationError(
                messages.ROLENAME_ALREADY_EXISTS
            )
        return role_name

    class Meta:
        model = Role
        fields = (
            "id", "role_name", "permissions",
            "role_importance", "created_on", "is_active")


class RoleImportSerializer(serializers.ModelSerializer):
    role_name = serializers.CharField(
        min_length=2,
        max_length=30,
        required=True
    )

    role_importance = serializers.IntegerField(
        min_value=0,
        max_value=10,
        required=True
    )
    is_active = serializers.CharField(required=False)

    def validate_role_name(self, role_name):
        if role_name.lower() in ['client', 'superadmin', 'driver', 'openapi']:
            raise serializers.ValidationError(
                messages.ROLE_NAME_NOT_ALLOWED
            )
        site_id = self.context['site_id']
        if Role.objects.filter(role_name=role_name, site_id=site_id).exists():
            raise serializers.ValidationError(
                messages.ROLENAME_ALREADY_EXISTS
            )
        return role_name

    def validate_is_active(self, is_active):
        if len(is_active) == 0:
            return True
        if is_active.strip().capitalize() == "True":
            return True
        elif is_active.strip().capitalize() == "False":
            return False
        else:
            raise serializers.ValidationError("Invalid Is Active option. True/False")

    class Meta:
        model = Role
        fields = (
            "id", "role_name", "permissions",
            "role_importance", "created_on", "is_active")


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
        if user and not user.is_user_active():
            raise serializers.ValidationError(
                self.error_messages['inactive_account']
            )
        self.user = authenticate(username=attrs.get(User.USERNAME_FIELD),
                                 password=attrs.get('password'))
        if not self.user:
            raise serializers.ValidationError(
                self.error_messages['invalid_credentials'])
        if self.user and self.user.role:
            if self.user.role.role_name.lower() != 'openapi':
                if self.context['request'].imei and self.context['request'].imei != 'Demo':
                    if self.context['request'].is_android_app:
                        if not self.user.has_access_mobile_dashboard:
                            raise serializers.ValidationError(
                                self.error_messages['no_access_for_mobile']
                            )
                        if self.user.imei_number:
                            if not (self.user.imei_number == self.context['request'].imei):
                                raise serializers.ValidationError(
                                    self.error_messages['device_not_registered']
                                )
                        else:
                            self.user.imei_number = self.context['request'].imei
                            self.user.save()
                else:
                    if not self.context['request'].is_android_app and not self.user.has_access_web_dashboard:
                        raise serializers.ValidationError(
                            self.error_messages['no_access_for_web']
                        )
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
    phone_number = PhoneNumberField()
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
    no_of_employees = serializers.IntegerField(
        min_value=0
    )

    def validate_username(self, username):
        if User.objects.filter(username=username):
            raise serializers.ValidationError(
                messages.USERNAME_ALREADY_EXISTS
            )
        return username

    def validate_phone_number(self, phone_number):
        if User.objects.filter(phone_number=phone_number):
            raise serializers.ValidationError(
                messages.PHONE_NUMBER_ALREADY_EXISTS
            )
        try:
            normalized_number = list(filter(None, phone_number.as_e164.split("+")))
            assert 8 <= len(normalized_number[0]) <= 13
        except AssertionError:
            raise serializers.ValidationError(
                messages.PHONE_MAX_MIN_VALIDATION_MESSAGE
            )
        except Exception:
            pass

        return phone_number

    def validate_email(self, email):
        if User.objects.filter(email=email):
            raise serializers.ValidationError(
                messages.EMAIL_ALREADY_EXITS
            )
        return email

    class Meta:
        model = User
        fields = (
            'username', 'email', 'phone_number', 'last_name',
            'password', 'id', 'first_name', 'no_of_employees'
        )
        extra_kwargs = {'phone_number': {'required': True},
                        'username': {'required': True}
                        }

    def create(self, validated_data):
        role = Role.objects.filter(
            role_name="Client",
            site_id=0
        ).first()
        validated_data['role'] = role
        user = User.objects.create_client(**validated_data)
        try:
            user.save()
            return user
        except (ValidationError, AssertionError, AttributeError):
            raise serializers.ValidationError(user)


class ChangePasswordSerializer(serializers.Serializer):
    """ change password serializer """
    new_password = serializers.CharField(write_only=True, min_length=6,
                                         validators=[
                                             valid.validate_password_field])
    old_password = serializers.CharField(write_only=True, min_length=6)

    def validate_old_password(self, attrs):
        if self.context['request'].user.check_password(attrs):
            return attrs
        else:
            raise serializers.ValidationError(messages.WRONG_OLD_PASSWORD)

    def validate_new_password(self, data):

        if self.context['request'].user.check_password(data):
            raise exceptions.ValidationError(messages.SAME_PASSWORD_AS_OLD)

        try:
            assert len(data) != 0

        except AssertionError:
            raise exceptions.ValidationError(["""New password
                                             should not be empty"""])

        return data


class OtpSerializer(serializers.Serializer):
    """ user otp verify serializer """
    id = serializers.IntegerField(min_value=0, label="User Id")
    otp = serializers.CharField(max_length=5)

    def validate_otp(self, value):
        user = self.context['user']
        try:
            self.user_otp = UserOtp.objects.get_user_otp_by_otp_and_user(
                value, user)
        except UserOtp.DoesNotExist:
            raise serializers.ValidationError(messages.INVALID_OTP)
        return value


class OtpVerifyPasswordResetSerializer(serializers.Serializer):
    """ verify otp and change password """
    id = serializers.IntegerField(label="User Id", min_value=0)
    otp = serializers.CharField(max_length=5)
    new_password = serializers.CharField(max_length=255,
                                         min_length=6,
                                         validators=[
                                             valid.validate_password_field])

    def validate_otp(self, value):
        user = self.context['user']
        try:
            self.user_otp = UserOtp.objects.get_user_otp_by_otp_and_user(
                value, user)
        except UserOtp.DoesNotExist:
            raise serializers.ValidationError(messages.INVALID_OTP)
        return value


class ForgotPasswordSerializer(serializers.Serializer):
    email = CustomEmailSerializerField()

    def validate_email(self, value):
        try:
            self.user = User.objects.get_user_by_email(value)
        except User.DoesNotExist:
            raise serializers.ValidationError(messages.UNREGISTERED_EMAIL)
        return value


class PasswordResetSerializer(serializers.Serializer):
    id = serializers.IntegerField(label="User Id", min_value=0)
    new_password = serializers.CharField(min_length=6,
                                         validators=[
                                             valid.validate_password_field])

    def validate_id(self, id):
        if not User.objects.filter(id=id):
            raise serializers.ValidationError(
                messages.USER_DOES_NOT_EXIST
            )
        return id


class UserSerializer(serializers.ModelSerializer):
    """
        User serializer for user ModelViewSet
    """
    first_name = serializers.CharField(
        min_length=2,
        max_length=50,
        required=True
    )
    last_name = serializers.CharField(
        min_length=2,
        max_length=50,
        required=False,
        allow_null=True,
        allow_blank=True
    )
    username = serializers.CharField(
        min_length=1,
        max_length=30,
        required=True
    )
    profile_pic = serializers.ImageField(
        required=False,
        validators=[valid.validate_file_extension]
    )
    license_number = serializers.CharField(
        min_length=5,
        max_length=50,
        required=False,
        allow_null=True,
        allow_blank=True
    )
    imei_number = serializers.CharField(
        min_length=5,
        max_length=50,
        required=False,
        allow_null=True,
        allow_blank=True
    )
    account_id = serializers.IntegerField(min_value=0)
    package_id = serializers.IntegerField(min_value=0, required=False)
    password = serializers.CharField(write_only=True, min_length=6,
                                     validators=[valid.validate_password_field]
                                     )
    email = CustomEmailSerializerField()
    phone_number = PhoneNumberField(
        required=False,
        allow_null=True,
        allow_blank=True
    )
    remaining_days = serializers.SerializerMethodField()
    employee_id = serializers.CharField(
        max_length=100, allow_null=True,
        allow_blank=True, required=False
    )
    account_time_off_req_bracket = serializers.SerializerMethodField()
    off_days = serializers.JSONField(required=False)
    is_profile_editable = serializers.SerializerMethodField()
    is_biometric_authentication_needed = serializers.SerializerMethodField()

    class Meta:
        model = User
        exclude = ()

    def get_remaining_days(self, obj):
        if obj.renewal_date:
            return (obj.renewal_date - timezone.now().date()).days
        else:
            return None

    def get_account_time_off_req_bracket(self, obj):
        if obj.account_id:
            self.account_details = conf_req_handler.get_account_details(
                obj.account_id,
                obj.site_id
            )
            if self.account_details:
                return self.account_details.get('time_off_request_bracket')
        return None


    def validate_email(self, email):
        if User.objects.filter(email=email):
            raise serializers.ValidationError(
                messages.EMAIL_ALREADY_EXITS
            )
        return email

    def validate_username(self, username):
        if User.objects.filter(username=username):
            raise serializers.ValidationError(
                messages.USERNAME_ALREADY_EXISTS
            )
        return username

    def validate_role(self, role):
        if role and role.role_name.lower() in ['client', 'superadmin', 'openapi']:
            raise serializers.ValidationError(
                "User with this role can't be created"
            )
        if not role:
            raise serializers.ValidationError(
                "Role is required field"
            )
        return role

    def validate_phone_number(self, phone_number):
        if phone_number in ['', None]:
            return phone_number
        try:
            normalized_number = list(filter(None, phone_number.as_e164.split("+")))
            assert 8 <= len(normalized_number[0]) <= 13
        except AssertionError:
            raise serializers.ValidationError(
                messages.PHONE_MAX_MIN_VALIDATION_MESSAGE
            )
        except Exception as e:
            raise e

        return phone_number

    def get_is_profile_editable(self, obj):
        if obj.account_id:
            account_details = self.account_details
            if account_details:
                return account_details.get('is_profile_editable')
        return None

    def get_is_biometric_authentication_needed(self, obj):
        if obj.account_id:
            account_details = self.account_details
            if account_details:
                return account_details.get('biometric_auth')
        return None


class UserImportSerializer(serializers.ModelSerializer):
    """
        User Import serializer
    """
    first_name = serializers.CharField(
        min_length=2,
        max_length=50,
        required=True
    )
    last_name = serializers.CharField(
        min_length=2,
        max_length=50,
        required=False,
        allow_null=True,
        allow_blank=True
    )
    username = serializers.CharField(
        min_length=1,
        max_length=30,
        required=True
    )
    profile_pic = serializers.ImageField(
        required=False,
        validators=[valid.validate_file_extension]
    )
    license_number = serializers.CharField(
        min_length=5,
        max_length=50,
        required=False,
        allow_null=True,
        allow_blank=True
    )
    imei_number = serializers.CharField(
        min_length=5,
        max_length=50,
        required=False,
        allow_null=True,
        allow_blank=True
    )
    account_id = serializers.IntegerField(min_value=0)
    package_id = serializers.IntegerField(min_value=0, required=False)
    password = serializers.CharField(write_only=True, min_length=6,
                                     validators=[valid.validate_password_field]
                                     )
    email = CustomEmailSerializerField()
    phone_number = PhoneNumberField(
        required=False,
        allow_null=True,
        allow_blank=True
    )
    remaining_days = serializers.SerializerMethodField()
    employee_id = serializers.CharField(
        max_length=100, allow_null=True,
        allow_blank=True, required=False
    )
    account_time_off_req_bracket = serializers.SerializerMethodField()
    off_days = serializers.JSONField(required=False)

    class Meta:
        model = User
        exclude = ()

    def get_remaining_days(self, obj):
        if obj.renewal_date:
            return (obj.renewal_date - timezone.now().date()).days
        else:
            return None

    def get_account_time_off_req_bracket(self, obj):
        if obj.account_id:
            account_details = conf_req_handler.get_account_details(
                obj.account_id,
                obj.site_id
            )
            if account_details:
                return account_details.get('time_off_request_bracket')
        return None

    def validate_email(self, email):
        if User.objects.filter(email=email):
            raise serializers.ValidationError(
                messages.EMAIL_ALREADY_EXITS
            )
        return email

    def validate_username(self, username):

        if User.objects.filter(username=username):
            raise serializers.ValidationError(
                messages.USERNAME_ALREADY_EXISTS
            )
        try:
            int(username)
        except ValueError:
            return username
        raise serializers.ValidationError("Username must be a string")

    def validate_first_name(self, first_name):
        if not bool(first_name.strip()):
            raise serializers.ValidationError("first_name is mandatory")
        try:
            assert not re.search("\d", first_name)
        except AssertionError:
            raise serializers.ValidationError("first_name cannot contain numbers")
        return first_name

    def validate_last_name(self, last_name):
        try:
            assert not re.search("\d", last_name)
        except AssertionError:
            raise serializers.ValidationError("last_name cannot contain numbers")
        return last_name

    def validate_role(self, role):
        if role and role.role_name.lower() in ['client', 'superadmin', 'openapi']:
            raise serializers.ValidationError(
                "User with this role can't be created"
            )
        if not role:
            raise serializers.ValidationError(
                "Role is required field"
            )
        return role

    def validate_phone_number(self, phone_number):
        if phone_number in ['', None]:
            return phone_number
        try:
            normalized_number = list(filter(None, phone_number.as_e164.split("+")))
            assert 8 <= len(normalized_number[0]) <= 13
        except AssertionError:
            raise serializers.ValidationError(
                messages.PHONE_MAX_MIN_VALIDATION_MESSAGE
            )
        except Exception as e:
            raise e

        return phone_number


class UserDetailSerializer(UserSerializer):
    phone_number = serializers.SerializerMethodField(
        required=False,
    )

    def validate_phone_number(self, phone_number):
        try:
            normalized_number = list(filter(None, phone_number.as_e164.split("+")))
            assert 8 <= len(normalized_number[0]) <= 13
        except AssertionError:
            raise serializers.ValidationError(
                messages.PHONE_MAX_MIN_VALIDATION_MESSAGE
            )
        except Exception:
            pass

        return phone_number

    def get_phone_number(self, obj):
        if obj.phone_number in [None, '']:
            return None
        return {
            'country_code': "+" + str(obj.phone_number.country_code),
            'number': str(obj.phone_number.national_number)
        }


class UserUpdateSerializer(serializers.ModelSerializer):
    """
        User serializer for user ModelViewSet
    """
    email = CustomEmailSerializerField()
    phone_number = PhoneNumberField(
        required=False,
        allow_null=True,
        allow_blank=True
    )
    username = serializers.CharField(
        min_length=1,
        max_length=30,
        required=True
    )
    off_days = serializers.JSONField(required=False)

    class Meta:
        model = User
        exclude = (["password", ])

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


class UserListSerializer(serializers.ModelSerializer):
    """ admin user listing serializer """
    phone_number = serializers.SerializerMethodField()
    role_name = serializers.SerializerMethodField()
    team_name = serializers.SerializerMethodField()
    team_linking_id = serializers.SerializerMethodField()

    def get_role_name(self, obj):
        if obj.role:
            return obj.role.role_name
        else:
            return None

    def get_phone_number(self, obj):
        if obj.phone_number in [None, '']:
            return None
        return {
            'country_code': "+" + str(obj.phone_number.country_code),
            'number': str(obj.phone_number.national_number)
        }

    def get_team_name(self, obj):
        team_name = []
        request = self.context.get('request')
        if request and request.query_params.get('get_team_names'):
            teams = obj.team.all()
            if teams:
                for i in teams:
                    team_name.append(i.team_name)
        return team_name

    def get_team_linking_id(self, obj):
        team_linking_id = []
        request = self.context.get('request')
        if request and request.query_params.get('get_team_linking_id'):
            teams = obj.team.all()
            if teams:
                for i in teams:
                    if i.linking_id:
                        team_linking_id.append(i.linking_id)
        return team_linking_id

    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'role_name', 'role',
                  'account_id', 'phone_number', 'email', 'is_active',
                  'no_of_employees', 'username', 'team', 'license_number',
                  'imei_number', 'employee_id', 'has_access_mobile_dashboard',
                  'has_access_web_dashboard', 'off_days', 'team_linking_id',
                  'hidden_on_scheduler', 'linking_id', 'team_name', 'site_id')
        read_only_fields = fields


class UserListSuperAdminSerializer(serializers.ModelSerializer):
    """ super admin user listing serializer """
    phone_number = serializers.SerializerMethodField()
    role_name = serializers.SerializerMethodField()

    def get_role_name(self, obj):
        if obj.role:
            return obj.role.role_name
        else:
            return None

    def get_phone_number(self, obj):
        if obj.phone_number in [None, '']:
            return None
        return {
            'country_code': "+" + str(obj.phone_number.country_code),
            'number': str(obj.phone_number.national_number)
        }

    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'role_name',
                  'account_id', 'phone_number', 'email', 'is_active',
                  'no_of_employees', 'username', 'team', 'license_number',
                  'imei_number', 'employee_id', 'has_access_mobile_dashboard',
                  'has_access_web_dashboard', 'off_days', 'address', 'package_id',
                  'city', 'state', 'country', 'pin_code', 'site_id',
                  'hidden_on_scheduler', 'linking_id')
        read_only_fields = fields


class UserIdSerialiazer(serializers.ModelSerializer):
    """ serializer for the user auto completed seacrh api  """
    email = CustomEmailSerializerField()

    class Meta:
        model = User
        fields = ('id', 'email', 'username')


class RegistrationConfirmSerializer(serializers.Serializer):
    otp = serializers.CharField(max_length=5)
    phone_number = PhoneNumberField()

    def validate(self, data):
        otp = data['otp']
        try:
            user = User.objects.get(phone_number=data['phone_number'])
            self.user_otp = UserOtp.objects.get_user_otp_by_otp_and_user(
                otp, user)
        except UserOtp.DoesNotExist:
            raise serializers.ValidationError(messages.INVALID_OTP)
        except User.DoesNotExist:
            raise serializers.ValidationError(
                messages.PHONE_NUMBER_VALIDATION_ERROR)
        created = self.user_otp.created
        current_datetime = timezone.now()
        last = (current_datetime - created).seconds
        if last > settings.SESSION_IDLE_TIMEOUT:
            raise exceptions.ValidationError(messages.INVALID_OTP)
        return data


class ResendOtpSerilizer(serializers.Serializer):
    id = serializers.IntegerField(label="User Id", min_value=0)


class UserAlertPreferenceSerializer(serializers.Serializer):
    clock_in_out_alert_mode = serializers.JSONField(required=False)
    overtime_alert_mode = serializers.JSONField(required=False)
    shift_alert_mode = serializers.JSONField(required=False)
    hours_before_shift_alert = serializers.IntegerField(
        required=False,
        min_value=0)

    class Meta:
        fields = '__all__'
        swagger_schema_fields = {
            'example': {
                'clock_in_out_alert_mode': {
                    "email": True,
                    "sms": False
                },
                'overtime_alert_mode': {
                    "email": True,
                    "sms": True
                },
                'shift_alert_mode': {
                    "email": True,
                    "sms": True
                },
                'hours_before_shift_alert': 2
            }}

    def validate(self, attrs):
        for key, value in attrs.items():
            if isinstance(value, dict):
                valid.validate_user_alert_field(value)
        return attrs


class MultipleIdDataSerializer(serializers.Serializer):
    ids = serializers.ListField(
        child=serializers.IntegerField(
            min_value=0
        ),
        required=True
    )
    key = serializers.CharField(max_length=20, required=True)


class UploadSerializer(serializers.Serializer):
    csv_file = serializers.FileField()


class ExportSerializer(serializers.Serializer):
    model = serializers.CharField(max_length=10, required=True)


class DownloadSerializer(serializers.Serializer):
    task_id = serializers.CharField(max_length=15, required=True)


class UserReadSerializer(serializers.ModelSerializer):
    team = serializers.SerializerMethodField()
    role_name = serializers.SerializerMethodField()

    def get_role_name(self, obj):
        if obj.role:
            return obj.role.role_name
        else:
            return None

    def get_team(self, obj):
        return [i.id for i in obj.team.all()]

    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name', 'team',
                  'profile_pic', 'role_name', 'off_days',
                  'hidden_on_scheduler', 'linking_id')
        read_only_fields = fields


class TestUserSerializer(serializers.ModelSerializer):
    """
        User serializer for user ModelViewSet
    """
    username = serializers.CharField(
        min_length=1,
        max_length=30,
        required=True
    )
    password = serializers.CharField(write_only=True, min_length=6,
                                     validators=[valid.validate_password_field]
                                     )
    email = CustomEmailSerializerField()
    phone_number = PhoneNumberField(
        required=False,
        allow_null=True,
        allow_blank=True
    )

    class Meta:
        model = User
        exclude = ()

    def validate_email(self, email):
        if User.objects.filter(email=email):
            raise serializers.ValidationError(
                messages.EMAIL_ALREADY_EXITS
            )
        return email

    def validate_phone_number(self, phone_number):
        if phone_number in ['', None]:
            return phone_number
        try:
            normalized_number = list(filter(None, phone_number.as_e164.split("+")))
            assert 8 <= len(normalized_number[0]) <= 13
        except AssertionError:
            raise serializers.ValidationError(
                messages.PHONE_MAX_MIN_VALIDATION_MESSAGE
            )
        except Exception as e:
            raise e
        return phone_number

    def validate_username(self, username):
        if User.objects.filter(username=username):
            raise serializers.ValidationError(
                messages.USERNAME_ALREADY_EXISTS
            )
        return username


class TestUserUpdateSerializer(serializers.ModelSerializer):
    username = serializers.CharField(
        min_length=1,
        max_length=30,
        required=True
    )
    email = CustomEmailSerializerField()
    phone_number = PhoneNumberField(
        required=False,
        allow_null=True,
        allow_blank=True
    )

    class Meta:
        model = User
        exclude = ()

    def validate_email(self, email):
        if User.objects.filter(email=email):
            raise serializers.ValidationError(
                messages.EMAIL_ALREADY_EXITS
            )
        return email

    def validate_phone_number(self, phone_number):
        if phone_number in ['', None]:
            return phone_number
        try:
            normalized_number = list(filter(None, phone_number.as_e164.split("+")))
            assert 8 <= len(normalized_number[0]) <= 13
        except AssertionError:
            raise serializers.ValidationError(
                messages.PHONE_MAX_MIN_VALIDATION_MESSAGE
            )
        except Exception as e:
            raise e
        return phone_number

    def validate_username(self, username):
        if User.objects.filter(username=username):
            raise serializers.ValidationError(
                messages.USERNAME_ALREADY_EXISTS
            )
        return username


class RequestedDownloadSerializer(serializers.ModelSerializer):
    class Meta:
        model = RequestedDownload
        fields = "__all__"


class ShiftTeamDetailSerializer(serializers.ModelSerializer):
    jobsite_data = serializers.SerializerMethodField()
    geo_fence_data = serializers.SerializerMethodField()
    team_members_data = serializers.SerializerMethodField()

    def get_jobsite_data(self, obj):
        poi_data = conf_req_handler.get_poi_for_team(
            obj.id, obj.site_id
        )
        return poi_data

    def get_geo_fence_data(self, obj):
        if obj.geo_area_id:
            geo_fence_data = conf_req_handler.get_geo_fence_detail(
                obj.geo_area_id, obj.site_id
            )
            if geo_fence_data:
                return geo_fence_data
        return None

    def get_team_members_data(self, obj):
        request = self.context.get('request')
        user_qs = User.objects.filter(
            site_id=obj.site_id,
            is_active=True,
            team=obj
        )
        hidden_on_scheduler = request.query_params.get(
            'hidden_on_scheduler', None)
        if hidden_on_scheduler in [True, 'true', False, 'false']:
            if hidden_on_scheduler in [True, 'true']:
                user_qs = user_qs.filter(
                    hidden_on_scheduler=True
                )
            else:
                user_qs = user_qs.filter(
                    hidden_on_scheduler=False
                )
        data = UserListSerializer(user_qs, many=True).data
        return data

    class Meta:
        model = Team
        fields = (
            "id", "team_name", "jobsite_data", "geo_fence_data",
            "team_members_data", "linking_id"
        )


class AppVersionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AppVersion
        fields = ('app_version',)


class UserMinimalDataSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ('id', 'first_name', 'last_name')


class ThrottlingListSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThrottlingModel
        fields = '__all__'
