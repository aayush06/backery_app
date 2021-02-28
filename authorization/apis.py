import json
import uuid
import redis
import os

from django.db.models import Q
from django.http import Http404
from django.template.loader import get_template
from django.utils import timezone
from django.contrib.auth import user_logged_in
from django_filters import rest_framework as filters_rest
from drf_yasg.utils import swagger_auto_schema
from rest_framework import (filters, generics, permissions, exceptions,
                            response, status, views, viewsets)
from rest_framework.viewsets import mixins

from authorization.utils.helper_methods import chk_user_can_be_assigned_account
from authorization.models import (Permission, Role, User, ThrottlingModel,
                                  UserOtp, UserAlertPreferences,
                                  UserSiteManager, RequestedDownload, AppVersion)
from authorization.serializers import (ChangePasswordSerializer,
                                       ForgotPasswordSerializer,
                                       LoginSerializer, OtpSerializer,
                                       PasswordResetSerializer,
                                       PermissionSerializer,
                                       RegistrationSerializer,
                                       RoleCreateUpdateSerializer,
                                       RoleDetailSerializer, RoleSerializer,
                                       UserListSerializer, UserSerializer,
                                       UserUpdateSerializer,
                                       OtpVerifyPasswordResetSerializer,
                                       ResendOtpSerilizer,
                                       UserAlertPreferenceSerializer,
                                       MultipleIdDataSerializer,
                                       UploadSerializer,
                                       TestUserSerializer,
                                       TestUserUpdateSerializer,
                                       UserReadSerializer,
                                       RequestedDownloadSerializer,
                                       ShiftTeamDetailSerializer,
                                       UserDetailSerializer, UserListSuperAdminSerializer, AppVersionSerializer,
                                       UserMinimalDataSerializer,
                                       ThrottlingListSerializer)
from authorization.utils.filters import (UserFilter, RoleFilter,
                                         UserByTeamFilterClass)
from authorization.utils import messages
from helpers.mixins import ExportMixin, DownloadMixin
from helpers.permissions import RoleAllowedPerm
from helpers.requests_handler import (NotificationRequestHandler,
                                      ConfigurationRequestHandler)
from helpers import tasks
from team.models import Team

notification_req_handler = NotificationRequestHandler()
conf_req_handler = ConfigurationRequestHandler()


class PermissionViewSet(viewsets.ModelViewSet):
    """ permission model view """

    permission_classes = (permissions.IsAuthenticated, )
    http_method_names = ["get"]
    extra_perms_map = {
        'GET': ["can_view_permission"]
    }
    filter_backends = (filters_rest.DjangoFilterBackend,
                       filters.SearchFilter,
                       filters.OrderingFilter,
                       )
    search_fields = ('permission_name',)
    ordering_fields = ('id',)
    model = Permission
    serializer_class = PermissionSerializer

    def get_queryset(self):
        queryset = self.model.objects.filter(
            ~Q(permission_name__icontains='access_open_api')
        )
        if self.action == 'list' and self.request.user.role.role_name.lower() != 'superadmin':
            queryset = queryset.filter(
                ~Q(Q(permission_name__icontains='feature') & Q(
                    permission_name__icontains='package'))
            )
        return queryset


class RoleViewSet(viewsets.ModelViewSet):
    """ role model view """

    permission_classes = (permissions.IsAuthenticated, RoleAllowedPerm, )
    model = Role
    filter_backends = (filters_rest.DjangoFilterBackend,
                       filters.SearchFilter,
                       filters.OrderingFilter,
                       )
    filter_class = RoleFilter
    search_fields = ('role_name',)
    ordering_fields = ('role_name',)
    extra_perms_map = {
        'GET': ["can_view_role"],
        'POST': ["can_create_role"],
        'PUT': ["can_edit_role"],
        'PATCH': ["can_edit_role"],
        'DELETE': ["can_deactivate_role"]
    }

    def get_queryset(self):
        site_id = self.request.site_id
        if self.request.user.is_superadmin:
            return self.model.objects.filter(
                ~Q(role_name__iexact="openapi")
            )
        else:
            return self.model.objects.filter(
                Q(site_id=site_id) |
                Q(site_id=0)
            ).filter(~Q(role_name__iexact="openapi"))

    def get_serializer_class(self):
        """
            serializer for listing, and other for creation
            , deletion, retrieving, updating
        """
        if self.action in ['retrieve']:
            return RoleDetailSerializer
        if self.request.method in ['POST', 'PUT', 'PATCH']:
            return RoleCreateUpdateSerializer
        else:
            return RoleSerializer

    def perform_create(self, serializer):
        instance = serializer.save()
        instance.site_id = self.request.site_id
        instance.save()

    def perform_update(self, serializer):
        instance = self.get_object()
        if instance.role_name.lower in ['client', 'superadmin', 'driver', 'openapi']:
            raise exceptions.ValidationError("System roles are non-editable")
        serializer.save()

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.role_name in ['Client', 'SuperAdmin', 'Driver']:
            raise exceptions.ValidationError(
                "System roles can't be deactivated")
        instance.set_role_inactive()
        instance.save()
        return response.Response(status=status.HTTP_204_NO_CONTENT)


class LoginView(generics.GenericAPIView):
    """ Endpoint for the user login """

    permission_classes = (permissions.AllowAny,)
    serializer_class = LoginSerializer

    def post(self, request, *args, **kargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.user
            response_dict = dict()
            auth_token, permissions, account_timezone = user.get_jwt_token_for_user()
            response_dict["auth_token"] = auth_token
            response_dict["permissions"] = permissions
            response_dict["is_superadmin"] = user.is_superadmin
            response_dict["is_client"] = user.is_client
            response_dict["id"] = user.id
            response_dict["account_timezone"] = account_timezone
            response_dict["last_login"] = user.last_login
            response_dict["linking_id"] = user.linking_id
            if user.site_id:
                response_dict["site_id"] = user.site_id
            else:
                site_obj = UserSiteManager.objects.filter(
                    site_manager=user).first()
                response_dict["site_id"] = site_obj.id
            return response.Response(
                data=response_dict,
                status=status.HTTP_200_OK,
            )


class MyAccountView(generics.RetrieveAPIView):
    """endpoint to get user profile"""

    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = UserDetailSerializer

    def get(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            instance=request.user, context={'request': request})
        return response.Response(serializer.data, status=status.HTTP_200_OK)


class UserRegistrationView(generics.CreateAPIView):
    """ endpoint to register user """

    permission_classes = (permissions.AllowAny,)
    serializer_class = RegistrationSerializer

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            site_id = UserSiteManager.objects.create(site_manager=user)
            response_dict = dict()
            auth_token, permissions, account_timezone = user.get_jwt_token_for_user()
            response_dict["auth_token"] = auth_token
            response_dict["permissions"] = permissions
            response_dict["is_superadmin"] = user.is_superadmin
            response_dict["is_client"] = user.is_client
            response_dict["last_login"] = user.last_login
            response_dict["account_timezone"] = account_timezone
            response_dict["site_id"] = site_id.id
            user.site_id = site_id.id
            user.save()
            data = serializer.data
            data.update(response_dict)
            return response.Response(
                data,
                status=status.HTTP_201_CREATED,
            )
        else:
            return response.Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )


class UserViewSet(viewsets.ModelViewSet):
    """ User model view """

    permission_classes = (permissions.IsAuthenticated, RoleAllowedPerm,)
    model = User
    filter_backends = (filters_rest.DjangoFilterBackend,
                       filters.SearchFilter,
                       filters.OrderingFilter,
                       )
    filter_class = UserFilter
    search_fields = ('first_name', 'last_name',
                     'username', 'employee_id', 'license_number',
                     'linking_id')
    ordering_fields = ('first_name', 'last_name', 'email')

    extra_perms_map = {
        'GET': ["can_view_user"],
        'POST': ["can_create_user"],
        'PUT': ["can_edit_user"],
        'PATCH': ["can_edit_user"],
        'DELETE': ["can_deactivate_user"]
    }

    def get_queryset(self):
        site_id = self.request.site_id
        if site_id.lower() == 'system':
            return self.model.objects.filter(
                ~Q(role__role_name__iexact='openapi')
            )
        if self.request.user.is_superadmin or self.request.query_params.get('user_id') or self.kwargs.get('pk'):
            return self.model.objects.filter(~Q(role__role_name__iexact='openapi')).select_related('role').prefetch_related('team')
        else:
            return self.model.objects.filter(
                ~Q(role__role_name__iexact='openapi'),
                site_id=site_id
            ).select_related('role').prefetch_related('team')

    def list(self, request, *args, **kwargs):
        """ custom list method """
        remove_pagination = request.query_params.get('remove_pagination', None)
        if remove_pagination:
            self.pagination_class = None

        return super(UserViewSet, self).list(request, *args, **kwargs)

    def get_serializer_class(self):
        """
            serializer for listing, and other for creation, deletion
            ,retrieving, updating
        """
        if self.request.method == 'GET' and not self.kwargs.get('pk'):
            if self.request.query_params.get('only_name'):
                return UserMinimalDataSerializer
            if self.request.user.is_superadmin:
                return UserListSuperAdminSerializer
            else:
                return UserListSerializer
        elif self.request.method == 'PUT' or self.request.method == 'PATCH':
            return UserUpdateSerializer
        elif self.request.method == 'GET' and self.kwargs.get('pk'):
            return UserDetailSerializer
        else:
            return UserSerializer

    def create(self, request, *args, **kwargs):
        form_data = False
        if any(map(request.content_type.__contains__, ["multipart/form-data"])):
            request.data._mutable = True
            team = request.data.get('team', '[]')
            team = json.loads(team)
            if 'team' in request.data.keys():
                request.data.pop('team')
            form_data = True
        serializer = self.get_serializer_class()
        serializer = serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            if form_data:
                serializer.validated_data['team'] = team
            validated_data = serializer.validated_data
            flag, linking_id_mandatory = chk_user_can_be_assigned_account(
                validated_data.get('account_id'), request.site_id
            )
            if not flag:
                raise exceptions.ValidationError(
                    "No. of users specified in account exceeds"
                )
            if linking_id_mandatory and not validated_data.get("linking_id"):
                raise exceptions.ValidationError(
                    "Linking id configured as mandatory in account"
                )
            if validated_data.get("linking_id"):
                user_qs = User.objects.filter(
                    linking_id=validated_data.get("linking_id"),
                    site_id=request.site_id
                ).exclude(Q(
                    linking_id__isnull=True) | Q(
                        linking_id=''
                    ))
                if user_qs:
                    raise exceptions.ValidationError(
                        "User with this linking id already exists."
                    )
            select_all = request.data.get('select_all')
            if select_all:
                excluded_members = request.data.get('excluded_members', '')
                if excluded_members is not '':
                    excluded_members = excluded_members.split(",")
                    team = list(Team.objects.filter(
                        site_id=request.site_id, is_active=True,
                        account_id=validated_data.get('account_id')
                    ).exclude(id__in=excluded_members).values_list('id', flat=True))
                else:
                    team = list(Team.objects.filter(
                        site_id=request.site_id, is_active=True,
                        account_id=validated_data.get('account_id')
                    ).values_list('id', flat=True))
            off_days = request.data.get("off_days", [])
            instance = serializer.save()
            instance.set_password(serializer.validated_data['password'])
            instance.set_active()
            site_id = self.request.site_id
            instance.site_id = site_id
            instance.team.set(team)
            instance.save()
            if off_days:
                tasks.create_future_off_days_on_user_create_edit.delay(
                    instance.id, validated_data.get('account_id'),
                    off_days, request.site_id
                )
            return response.Response(
                serializer.data,
                status=status.HTTP_201_CREATED
            )
        else:
            return response.Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )

    def perform_update(self, serializer):
        instance = self.get_object()
        initial_team = list(instance.team.all().values_list('id', flat=True))
        initial_account_id = instance.account_id
        if instance.off_days:
            initial_off_days = list(instance.off_days)
        else:
            initial_off_days = []
        validated_data = serializer.validated_data
        account_id = validated_data.get('account_id', None)
        if account_id:
            flag, linking_id_mandatory = chk_user_can_be_assigned_account(
                account_id, self.request.site_id, instance.id
            )
            if not flag:
                raise exceptions.ValidationError(
                    "No. of users specified in account exceeds"
                )
            if linking_id_mandatory and not (validated_data.get("linking_id") or instance.linking_id):
                raise exceptions.ValidationError(
                    "Linking id is configured as mandatory in account"
                )
        else:
            if initial_account_id:
                flag, linking_id_mandatory = chk_user_can_be_assigned_account(
                    initial_account_id, self.request.site_id, instance.id
                )
                if not flag:
                    raise exceptions.ValidationError(
                        "No. of users specified in account exceeds"
                    )
                if linking_id_mandatory and not (validated_data.get("linking_id") or instance.linking_id):
                    raise exceptions.ValidationError(
                        "Linking id is configured as mandatory in account"
                    )
        if validated_data.get("linking_id"):
            user_qs = self.model.objects.filter(
                linking_id=validated_data.get("linking_id"),
                site_id=self.request.site_id
            ).exclude(Q(
                linking_id__isnull=True) | Q(
                    linking_id=''
                )).exclude(
                    id=instance.id
                )
            if user_qs:
                raise exceptions.ValidationError(
                    "User with this linking id already exists."
                )
        no_of_employees = validated_data.get('no_of_employees', None)
        if no_of_employees:
            user_package = instance.package_id
            if user_package:
                package_data = conf_req_handler.get_package_details(
                    user_package,
                    self.request.site_id
                )
                if package_data:
                    no_of_user_in_package = package_data['number_of_users']
                    if no_of_user_in_package and no_of_employees > no_of_user_in_package:
                        raise exceptions.ValidationError(
                            "Upgrade your package as users exceeds from specified limit in package"
                        )
            no_of_users_linked = self.model.objects.filter(
                site_id=self.request.site_id
            ).count()
            if no_of_users_linked and no_of_employees < no_of_users_linked:
                raise exceptions.ValidationError(
                    "You have already assigned %s users, so you can't assign no. of employees lesser than that." % str(no_of_users_linked)
                )
        is_active = validated_data.get('is_active', None)
        if isinstance(is_active, bool) and is_active == False:
            tasks.migrate_shift_to_open.delay(
                [instance.id], self.request.site_id
            )
        select_all = self.request.data.get('select_all')
        if select_all:
            excluded_members = self.request.data.get('excluded_members', [])
            final_team = list(Team.objects.filter(site_id=self.request.site_id, is_active=True,
                                                  account_id=account_id if account_id else initial_account_id).
                              exclude(id__in=excluded_members).values_list('id', flat=True))
        else:
            final_team = self.request.data.get('team', [])
        if 'select_all' and 'team' not in self.request.data.keys():
            final_team = initial_team
        if final_team:
            deleted_team = list(
                set(initial_team).symmetric_difference(
                    set(final_team)))
            if len(deleted_team) > 0:
                for i in deleted_team:
                    tasks.migrate_shift_to_open.delay(
                        [instance.id], self.request.site_id, team_id=i)
        final_off_days = self.request.data.get('off_days', [])
        if final_off_days or final_off_days in [[], ""]:
            changed_off_days = list(
                set(initial_off_days).symmetric_difference(
                    set(final_off_days)))
            if len(changed_off_days) > 0 or (account_id and account_id != initial_account_id):
                account_id = account_id if account_id else instance.account_id
                tasks.create_future_off_days_on_user_create_edit.delay(
                    instance.id, account_id,
                    final_off_days, self.request.site_id,
                    deleted=True
                )
        if "linking_id" in validated_data.keys():
            prev_linking_id = instance.linking_id
            current_linking_id = validated_data.get("linking_id")
            tasks.update_linking_id_data.delay(
                instance.id,
                self.request.site_id,
                prev_linking_id=prev_linking_id,
                current_linking_id=current_linking_id,
                module="user"
                )
        instance = serializer.save()
        instance.team.set(final_team)
        instance.save()

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.set_inactive()
        instance.save()
        return response.Response(status=status.HTTP_204_NO_CONTENT)


class UserVerifyOtp(views.APIView):
    """ endpoint for user otp verification """
    permission_classes = (permissions.AllowAny,)
    serializers_class = OtpSerializer

    @swagger_auto_schema(
        request_body=OtpSerializer,
        operation_id="Verify OTP")
    def post(self, request, *args, **kwargs):
        user_id = request.data["id"]
        try:
            user = User.objects.get_user_by_id(user_id)
        except User.DoesNotExist:
            raise Http404
        serializer = self.serializers_class(data=request.data, context={
                                            'request': request, 'user': user})

        if serializer.is_valid(raise_exception=True):
            user.is_active = True
            user.save()
            user_logged_in.send(
                sender=user.__class__, request=self.request, user=user)
            serializer.user_otp.delete()
            response_dict = dict()
            auth_token, permissions, account_timezone = user.get_jwt_token_for_user()
            response_dict["auth_token"] = auth_token
            response_dict["permissions"] = permissions
            response_dict["is_superadmin"] = user.is_superadmin
            response_dict["last_login"] = user.last_login
            response_dict["account_timezone"] = account_timezone
            return response.Response(
                response_dict,
                status=status.HTTP_200_OK,
            )


class ResendOtp(views.APIView):
    """ endpoint to resend otp to user """
    permission_classes = (permissions.AllowAny,)

    @swagger_auto_schema(
        request_body=ResendOtpSerilizer,
        operation_id="Resend otp")
    def post(self, request, *args, **kwargs):
        """ resend the otp to user """
        user_id = request.data["id"]
        try:
            user = User.objects.get_user_by_id(user_id)
        except User.DoesNotExist:
            raise Http404

        user_otp = user.generate_otp(email=user.email)
        full_name = user.first_name + " " + user.last_name
        email_message = f"Hi {full_name},<br/> Use {str(user_otp)} as one time password (OTP)" \
                        f" to change your password for the Waynaq account. Do not share this OTP to" \
                        f" anyone for security reasons." \
                        f" Valid for 15 minutes.<br/><br/> Thanks<br/> Waynaq Team<br/>"
        notification_req_handler.send_notification(
            "email", user.email, "User OTP Verification",
            get_template("otp.html").render(), email_message
        )

        return response.Response(
            {'msg': messages.OTP_SENT_SUCCESSFULLY},
            status=status.HTTP_200_OK)


class OtpVerifyPasswordResetAPIView(views.APIView):
    """ end point to reset password with otp after forgot password """
    permission_classes = (permissions.AllowAny,)
    serializers_class = OtpVerifyPasswordResetSerializer

    @swagger_auto_schema(
        request_body=OtpVerifyPasswordResetSerializer,
        operation_id="Verify Otp")
    def post(self, request, *args, **kwargs):
        user_id = request.data["id"]
        try:
            user = User.objects.get_user_by_id(user_id)
        except User.DoesNotExist:
            raise Http404
        serializer = self.serializers_class(data=request.data, context={
                                            'request': request, 'user': user})

        if serializer.is_valid(raise_exception=True):
            user.is_active = True
            user.set_password(request.data["new_password"])
            user.save()
            serializer.user_otp.delete()
            return response.Response(
                data={'summary': "password reset successfully"},
                status=status.HTTP_200_OK
            )


class ForgotPasswordAPIView(views.APIView):
    """ endpoint to send otp to email for forgot password """

    model = User
    serializer_class = ForgotPasswordSerializer
    permission_classes = (
        permissions.AllowAny,
    )
    queryset = User.objects.all()

    @swagger_auto_schema(
        request_body=ForgotPasswordSerializer,
        operation_id="Forgot password")
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.user
            user_otp = user.generate_otp(email=user.email)
            full_name = user.first_name + " " + user.last_name
            email_message = f"Hi {full_name},<br/> Use {str(user_otp)} as one time password (OTP)" \
                            f" to change your password for the Waynaq account. Do not share this OTP to" \
                            f" anyone for security reasons." \
                            f" Valid for 15 minutes.<br/><br/> Thanks<br/> Waynaq Team<br/>"
            notification_req_handler.send_notification(
                "email", user.email, "User OTP Verification",
                get_template("otp.html").render(), email_message
            )
            return response.Response(
                data={"id": user.id}, status=status.HTTP_200_OK)


class ChangePasswordView(views.APIView):

    """ change user password for authenticated user """
    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = ChangePasswordSerializer

    @swagger_auto_schema(
        request_body=ChangePasswordSerializer,
        operation_id="Change password")
    def post(self, request, *args, **kwargs):

        serializer = self.serializer_class(
            data=request.data, context={"request": request})
        if serializer.is_valid(raise_exception=True):
            request.user.set_password(
                serializer.validated_data["new_password"])
            request.user.is_active = True
            request.user.save()
            return response.Response({"msg": messages.PASSWORD_RESET_CONFIRM},
                                     status=status.HTTP_200_OK)


class PasswordResetView(views.APIView):
    """ reset user password """
    permission_classes = (permissions.AllowAny,)
    serializer_class = PasswordResetSerializer

    @swagger_auto_schema(
        request_body=PasswordResetSerializer,
        operation_id="Reset password")
    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={"request": request})
        if serializer.is_valid(raise_exception=True):
            user = User.objects.get_user_by_id(request.data["id"])
            user.is_active = True
            user.set_password(serializer.validated_data["new_password"])
            user.save()
            UserOtp.objects.get_all_otp_of_user(user).delete()
            return response.Response({"msg": messages.PASSWORD_RESET_CONFIRM},
                                     status=status.HTTP_200_OK)


class UserAlertPreferenceViewSet(generics.GenericAPIView):
    """ user alert preference model view """
    permission_classes = (permissions.IsAuthenticated, )
    http_method_names = ["get", "post"]
    serializer_class = UserAlertPreferenceSerializer

    def get(self, request, *args, **kwargs):
        user_pref_obj = UserAlertPreferences.objects.filter(
            user=request.user
        ).first()
        serializer = self.serializer_class(instance=user_pref_obj)
        return response.Response(
            serializer.data,
            status=status.HTTP_200_OK
        )

    def post(self, request, *args, **kwargs):
        request.data.update({
            "user": request.user.id
        })
        serializer = self.serializer_class(
            data=request.data, context={"request": request})
        if serializer.is_valid(raise_exception=True):
            user_pref_qs = UserAlertPreferences.objects.filter(
                user=request.user
            )
            if user_pref_qs:
                user_pref_qs.update(**serializer.validated_data)
            else:
                serializer.validated_data['user'] = request.user
                UserAlertPreferences.objects.create(
                    **serializer.validated_data)
            return response.Response(serializer.data,
                                     status=status.HTTP_201_CREATED)


class GetUserStoreManagerEmail(generics.GenericAPIView):
    """ get user store manager email """
    permission_classes = (permissions.IsAuthenticated, )
    http_method_names = ["get"]

    def get(self, request, *args, **kwargs):
        data = dict()
        data['email'] = []
        account_id = request.user.account_id
        if account_id:
            account_data = conf_req_handler.get_account_details(
                account_id,
                request.site_id
            )
            if account_data:
                company_email = account_data['company_email']
            if company_email:
                data['email'] = [company_email]
        return response.Response(
            data,
            status=status.HTTP_200_OK
        )


class MultipleTeamUserDeleteAPIView(generics.GenericAPIView):
    """ delete team/user handler """
    permission_classes = (permissions.IsAuthenticated, RoleAllowedPerm, )
    http_method_names = ["post"]

    @swagger_auto_schema(operation_id="multiple delete",
                         request_body=MultipleIdDataSerializer)
    def post(self, request, *args, **kwargs):
        key = request.data.get('key', None)
        if key:
            ids = request.data.get('ids', None)
            if ids:
                if key.lower() == 'team':
                    Team.objects.filter(id__in=ids).update(
                        is_active=False
                    )
                elif key.lower() == 'user':
                    User.objects.filter(id__in=ids).update(
                        is_active=False
                    )
                else:
                    return response.Response(
                        {"error": "key can be team/user only"},
                        status=status.HTTP_400_BAD_REQUEST
                    )
            else:
                return response.Response(
                    {"error": "ids is required field"},
                    status=status.HTTP_400_BAD_REQUEST
                )
        else:
            return response.Response(
                {
                    "error": "key is required filed"
                },
                status=status.HTTP_400_BAD_REQUEST
            )
        return response.Response(
            status=status.HTTP_204_NO_CONTENT
        )


class ExportAPIView(views.APIView, ExportMixin):
    """
        Export particular data
    """
    permission_classes = (RoleAllowedPerm, )
    filter_backends = (
        filters_rest.DjangoFilterBackend,
    )


class DownloadAPIView(views.APIView, DownloadMixin):
    """
        Pass task_id in query params to download the file
    """


class UserUploadAPIView(generics.CreateAPIView):
    """
        API to upload user data in csv format
    """
    model = 'User'
    app = 'authorization'
    permission_classes = (RoleAllowedPerm, )
    serializer_class = UploadSerializer
    extra_perms_map = {
        'POST': ["can_create_user"]
    }

    def post(self, request, *args, **kwargs):
        if request.FILES:
            csvfile = request.FILES['csv_file']
            if not csvfile.name.endswith('.csv'):
                raise Http404
        else:
            return response.Response("{'msg':'no file detected'}")
        site_id = self.request.site_id
        csvfile = csvfile.read().decode('utf-8')
        task = tasks.UploadUser()
        sync = False
        csv_length = len(list(filter(None, csvfile.split("\n"))))
        if csv_length - 1 > 1000:
            task = task.delay(csvfile, site_id, self.request.user.email, self.request.user.username)
        else:
            sync = True
            task_response = task.run(csvfile, site_id, self.request.user.email, self.request.user.username, sync=sync)

            return response.Response(task_response)

        return response.Response("User upload status will be sent to mail.")


class RoleUploadAPIView(generics.CreateAPIView):
    """
        API to upload role data in csv format
    """
    model = 'Role'
    app = 'authorization'
    permission_classes = (RoleAllowedPerm, )
    serializer_class = UploadSerializer

    def post(self, request, *args, **kwargs):
        if request.FILES:
            csvfile = request.FILES['csv_file']
            if not csvfile.name.endswith('.csv'):
                raise Http404
        else:
            return response.Response("{'msg':'no file detected'}")
        site_id = self.request.site_id
        csvfile = csvfile.read().decode('utf-8')
        task = tasks.UploadRole()
        sync = False
        csv_length = len(list(filter(None, csvfile.split("\n"))))
        if csv_length - 1 > 1000:
            task = task.delay(csvfile, site_id, self.request.user.email, self.request.user.username)
        else:
            sync = True
            task_response = task.run(csvfile, site_id, self.request.user.email, self.request.user.username, sync=sync)

            return response.Response(task_response)

        return response.Response("Role upload status will be sent to mail.")


class TeamUploadAPIView(generics.CreateAPIView):
    """
        API to upload team data in csv format
    """
    model = 'Team'
    app = 'team'
    permission_classes = (RoleAllowedPerm, )
    serializer_class = UploadSerializer

    def post(self, request, *args, **kwargs):
        if request.FILES:
            csvfile = request.FILES['csv_file']
            if not csvfile.name.endswith('.csv'):
                raise Http404
        else:
            return response.Response("{'msg':'no file detected'}")
        site_id = self.request.site_id
        csvfile = csvfile.read().decode('utf-8')
        task = tasks.UploadTeam()

        sync = False
        csv_length = len(list(filter(None, csvfile.split("\n"))))
        if csv_length - 1 > 1000:
            task = task.delay(csvfile, site_id,
                              email=self.request.user.email,
                              username=self.request.user.username)
        else:
            sync = True
            task_response = task.run(csvfile, site_id, sync=sync,
                                     email=self.request.user.email,
                                     username=self.request.user.username)

            return response.Response(task_response)

        return response.Response("Team upload status will be sent to mail.")


class TeamUploadUpdateAPIView(generics.CreateAPIView):
    """
        API to upload updated team data in csv format
    """
    model = 'Team'
    app = 'team'
    permission_classes = (RoleAllowedPerm, )
    serializer_class = UploadSerializer

    def post(self, request, *args, **kwargs):
        if request.FILES:
            csvfile = request.FILES['csv_file']
            if not csvfile.name.endswith('.csv'):
                raise Http404
        else:
            return response.Response("{'msg':'no file detected'}")
        site_id = self.request.site_id
        csvfile = csvfile.read().decode('utf-8')
        task = tasks.UploadUpdateTeam()

        sync = False
        csv_length = len(list(filter(None, csvfile.split("\n"))))
        if csv_length - 1 > 1000:
            task = task.delay(csvfile, site_id,
                              email=self.request.user.email,
                              username=self.request.user.username)
        else:
            sync = True
            task_response = task.run(csvfile, site_id, sync=sync,
                                     email=self.request.user.email,
                                     username=self.request.user.username)

            return response.Response(task_response)

        return response.Response("Team update upload status will be sent to mail.")


class UserReadViewSet(mixins.ListModelMixin,
                      viewsets.GenericViewSet):

    permission_classes = (permissions.IsAuthenticated, RoleAllowedPerm,)
    model = User
    filter_backends = (filters_rest.DjangoFilterBackend,
                       filters.SearchFilter,
                       filters.OrderingFilter,
                       )
    filter_class = UserFilter
    search_fields = ('first_name', 'last_name',
                     'username', 'employee_id', 'license_number',
                     'linking_id')
    ordering_fields = ('first_name', 'last_name')
    serializer_class = UserReadSerializer
    pagination_class = None

    extra_perms_map = {
        'GET': ["can_view_user"]
    }

    def get_queryset(self):
        site_id = self.request.site_id
        return self.model.objects.filter(
            ~Q(role__role_name__iexact='openapi'),
            site_id=site_id)


class TestUserViewSet(mixins.CreateModelMixin,
                      mixins.UpdateModelMixin,
                      viewsets.GenericViewSet):

    permission_classes = (permissions.AllowAny,)
    model = User

    def get_serializer_class(self):
        if self.request.method == 'PATCH':
            return TestUserUpdateSerializer
        else:
            return TestUserSerializer

    def get_queryset(self):
        site_id = self.request.site_id
        return self.model.objects.filter(
            ~Q(role__role_name__iexact='openapi'),
            site_id=site_id)

    def create(self, request, *args, **kwargs):
        role = Role.objects.filter(
            role_name__iexact='superadmin')
        if role:
            request.data.update({
                "role": role.first().id
            })
        else:
            raise exceptions.ValidationError("no superadmin role found")
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            validated_data = serializer.validated_data
            obj = self.model.objects.create(**validated_data)
            obj.set_password(validated_data.get('password'))
            site_id = UserSiteManager.objects.create(site_manager=obj)
            obj.team.set([])
            obj.site_id = site_id.id
            obj.save()
            return response.Response(
                {},
                status=status.HTTP_201_CREATED
            )
        else:
            return response.Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )


class UserExportAPIView(generics.CreateAPIView):
    """
        Extracting user data in the excel
    """
    permission_classes = (RoleAllowedPerm, )
    filter_backends = (
        filters_rest.DjangoFilterBackend,
    )

    def post(self, request, *args, **kwargs):

        account_id = self.request.data.get('account_id', None)
        is_active = self.request.data.get('is_active', None)
        team_id = self.request.data.get('team_id', None)
        role_id = self.request.data.get('role_id', None)
        has_linking_id = request.data.get('has_linking_id', None)

        download_request_obj = RequestedDownload.objects.create(
            requested_by=self.request.user.email)
        async_task = tasks.UploadUserExtract()
        async_task.delay(
            self.request.site_id, self.request.user.email,
            obj_id_list=[download_request_obj.id, ], account_id=account_id,
            is_active=is_active, team_id=team_id, role_id=role_id,
            has_linking_id=has_linking_id)
        return response.Response("excel link will be mailed to you.")


class RoleExportAPIView(generics.ListAPIView):
    """
        Extracting role data in the excel
    """
    permission_classes = (RoleAllowedPerm, )
    filter_backends = (filters_rest.DjangoFilterBackend,
                       filters.SearchFilter,
                       filters.OrderingFilter,
                       )
    filter_class = RoleFilter
    search_fields = ('role_name',)
    ordering_fields = ('role_name',)
    model = Role

    def get_queryset(self):
        site_id = self.request.site_id
        return self.model.objects.filter(
            ~Q(role_name__iexact='openapi') & Q(
            Q(site_id=site_id) |
            Q(site_id=0))
        )

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        serializer = RoleSerializer(data=queryset, many=True, context={'request':self.request})
        serializer.is_valid()
        download_request_obj = RequestedDownload.objects.create(
            requested_by=self.request.user.email)
        async_task = tasks.RoleDataExtract()
        async_task.delay(
            self.request.site_id, self.request.user.email,
            download_request_obj_id=download_request_obj.id, queryset=serializer.data)
        return response.Response("excel link will be mailed to you.")


class RequestedDownloadView(generics.ListAPIView):

    permission_classes = (permissions.IsAuthenticated,)
    model = RequestedDownload
    serializer_class = RequestedDownloadSerializer
    filter_backends = (filters_rest.DjangoFilterBackend,
                       filters.SearchFilter,
                       filters.OrderingFilter,)
    filter_fields = ('task_id', 'status', 'requested_by', 'requested_on')
    # extra_perms_map = {
    #     'GET': ["can_view_attendance"]
    # }

    def get_object(self):
        try:
            assert self.kwargs.get('request_id')
            request_obj = self.model.objects.get(id=uuid.UUID(self.kwargs.get('request_id')))
            return request_obj
        except Exception as e:
            raise exceptions.ValidationError(e.__str__())

    def get_queryset(self):
        return RequestedDownload.objects.all()

    def list(self, request, *args, **kwargs):

        if self.kwargs.get("request_id"):
            try:
                instance = self.get_object()
                serializer = self.get_serializer(instance)
                return response.Response(serializer.data)
            except Exception as e:
                raise e

        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        return response.Response(serializer.data)


class UsersByTeamView(generics.ListAPIView, generics.GenericAPIView):
    """
        Fetch users with respect to multiple teams
    """
    permission_classes = (permissions.IsAuthenticated,)
    model = User

    filter_backends = [
        filters_rest.DjangoFilterBackend,
        filters.SearchFilter,
        filters.OrderingFilter
    ]

    filterset_fields = ['team', 'account_id']
    search_fields = ['first_name', 'last_name']
    ordering_fields = ['first_name', 'last_name']

    filter_class = UserByTeamFilterClass

    serializer_class = UserListSerializer

    def get_queryset(self):
        site_id = self.request.site_id
        return self.model.objects.filter(
            ~Q(role__role_name__iexact='openapi'),
            site_id=site_id)

    def get(self, request, *args, **kwargs):

        data = self.filter_queryset(self.get_queryset())

        remove_pagination = request.query_params.get('remove_pagination', None)
        if remove_pagination:
            self.pagination_class = None

        page = self.paginate_queryset(data)
        if page is not None:
            serializer = UserListSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = UserListSerializer(data, many=True)
        return response.Response(serializer.data)


class AdminResetPassword(mixins.CreateModelMixin,
                         viewsets.GenericViewSet):

    permission_classes = (permissions.IsAuthenticated, RoleAllowedPerm,)
    model = User
    serializer_class = PasswordResetSerializer
    extra_perms_map = {
        'POST': ["can_edit_user"]
    }

    @swagger_auto_schema(
        request_body=PasswordResetSerializer,
        operation_id="Reset password")
    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={"request": request})
        if serializer.is_valid(raise_exception=True):
            user = User.objects.get_user_by_id(request.data.get("id"))
            user.set_password(serializer.validated_data["new_password"])
            user.save()
            UserOtp.objects.get_all_otp_of_user(user).delete()
            return response.Response({"msg": messages.PASSWORD_RESET_CONFIRM},
                                     status=status.HTTP_200_OK)


class TeamDetailViewSet(mixins.RetrieveModelMixin,
                        viewsets.GenericViewSet):

    model = Team
    serializer_class = ShiftTeamDetailSerializer

    def get_queryset(self):
        return self.model.objects.filter(
            site_id=self.request.site_id
        )


class AppVersionViewset(viewsets.ModelViewSet):
    pagination_class = None
    model = AppVersion
    queryset = AppVersion.objects.all()
    serializer_class = AppVersionSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return response.Response(
                request.data,
                status=status.HTTP_201_CREATED
            )
        else:
            return response.Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )


class MarkUserCurrentMonthOffDay(views.APIView):
    permission_classes = (permissions.IsAuthenticated, RoleAllowedPerm,)

    def post(self, request, *args, **kwargs):
        tasks.create_off_day_once.delay()
        return response.Response(
            {"success": True},
            status=status.HTTP_200_OK
        )


class UserOpenViewSet(mixins.ListModelMixin,
                      viewsets.GenericViewSet):
    model = User
    filter_backends = (filters_rest.DjangoFilterBackend,
                       filters.SearchFilter,
                       filters.OrderingFilter,
                       )
    filter_class = UserFilter
    search_fields = ('first_name', 'last_name',
                     'username', 'employee_id', 'license_number',
                     'linking_id')
    ordering_fields = ('first_name', 'last_name')
    serializer_class = UserListSerializer
    pagination_class = None

    def get_queryset(self):
        site_id = self.request.site_id
        if isinstance(site_id, str) and site_id == 'SYSTEM':
            return self.model.objects.filter(
                ~Q(role__role_name__iexact='openapi'))
        return self.model.objects.filter(
            ~Q(role__role_name__iexact='openapi'),
            site_id=site_id)


class OpenAPIAuthentication(generics.GenericAPIView):
    """ Endpoint for the open api login """

    permission_classes = (permissions.AllowAny,)
    serializer_class = LoginSerializer

    def post(self, request, *args, **kargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.user
            if user.role:
                if user.role.role_name.lower() != 'openapi':
                    return response.Response(
                        {
                            "error": "You do not have permission to perform this action"
                        },
                        status=status.HTTP_403_FORBIDDEN
                    )
            response_dict = dict()
            auth_token, permissions, account_timezone = user.get_jwt_token_for_user()
            response_dict["auth_token"] = auth_token
            throttling_qs = ThrottlingModel.objects.filter(
                user_id=user.id
            )
            if throttling_qs:
                throttling_obj = throttling_qs.first()
                throttling_obj.consumed_request_count = 0
                throttling_obj.executed_on = timezone.now()
                throttling_obj.save()
            else:
                ThrottlingModel.objects.create(
                    user_id=user.id,
                    consumed_request_count=0,
                    executed_on=timezone.now()
                )
            return response.Response(
                data=response_dict,
                status=status.HTTP_200_OK,
            )


class OpenAPIUserCreate(mixins.CreateModelMixin,
                        viewsets.GenericViewSet):

    permission_classes = (permissions.IsAuthenticated, RoleAllowedPerm,)
    model = User
    serializer_class = TestUserSerializer

    def get_queryset(self):
        site_id = self.request.site_id
        return self.model.objects.filter(
            site_id=site_id)

    def create(self, request, *args, **kwargs):
        role = Role.objects.filter(
            role_name__iexact='openapi')
        if role:
            request.data.update({
                "role": role.first().id
            })
        else:
            raise exceptions.ValidationError("no openapi role found")
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            validated_data = serializer.validated_data
            obj = self.model.objects.create(**validated_data)
            obj.set_password(validated_data.get('password'))
            obj.team.set([])
            obj.site_id = request.site_id
            obj.save()
            return response.Response(
                {},
                status=status.HTTP_201_CREATED
            )
        else:
            return response.Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )


class GetThrottlingLimit(views.APIView):
    """ Endpoint for the open api throttling limit """

    permission_classes = (permissions.IsAuthenticated, RoleAllowedPerm,)

    def get(self, request, *args, **kargs):
        user = request.user
        if user.role:
            if user.role.role_name.lower() != 'openapi':
                return response.Response(
                    {
                        "error": "You do not have permission to perform this action"
                    },
                    status=status.HTTP_403_FORBIDDEN
                )
        response_dict = dict()
        throttling_qs = ThrottlingModel.objects.filter(
            user_id=user.id
        )
        flag = True
        if throttling_qs:
            throttling_obj = throttling_qs.first()
            time_diff = int((timezone.now()-throttling_obj.executed_on).total_seconds())
            if throttling_obj.consumed_request_count <= 30 and time_diff <= 60:
                throttling_obj.consumed_request_count = throttling_obj.consumed_request_count+1
            elif throttling_obj.consumed_request_count <= 30 and time_diff >= 60:
                throttling_obj.consumed_request_count = 0
                throttling_obj.executed_on = timezone.now()
            elif throttling_obj.consumed_request_count > 30 and time_diff <= 60:
                throttling_obj.consumed_request_count = 0
                flag = False
            elif throttling_obj.consumed_request_count > 30 and time_diff > 60:
                throttling_obj.consumed_request_count = 0
                throttling_obj.executed_on = timezone.now()
                flag = False
            throttling_obj.save()
        else:
            ThrottlingModel.objects.create(
                user_id=user.id,
                consumed_request_count=1,
                executed_on=timezone.now()
            )
        if not flag:
            response_dict["allow"] = False
        else:
            response_dict["allow"] = True
        return response.Response(
            data=response_dict,
            status=status.HTTP_200_OK,
        )


class ListThrottlingModel(mixins.ListModelMixin,
                          viewsets.GenericViewSet):
    model = ThrottlingModel
    serializer_class = ThrottlingListSerializer
    pagination_class = None

    def get_queryset(self):
        return self.model.objects.all()


class RoleOpenViewSet(mixins.ListModelMixin,
                      viewsets.GenericViewSet):
    model = Role
    filter_backends = (filters_rest.DjangoFilterBackend,
                       filters.SearchFilter,
                       filters.OrderingFilter,
                       )
    filter_class = RoleFilter
    search_fields = ('role_name',)
    ordering_fields = ('role_name',)
    serializer_class = RoleSerializer
    pagination_class = None

    def get_queryset(self):
        site_id = self.request.site_id
        if isinstance(site_id, str) and site_id == 'SYSTEM':
            return self.model.objects.all()
        return self.model.objects.filter(site_id=site_id)


class RedisView(generics.ListAPIView):
    """endpoint to get user profile"""

    permission_classes = (permissions.IsAuthenticated,)
    serializer_class = UserSerializer

    def filter_user_data(self, redis_instance):
        user_data = list()

        if self.request.query_params.get('id'):
            user_id = self.request.query_params.get('id')
            for data in redis_instance.scan_iter(f"User_{user_id}*"):
                temp_user_info = json.loads(redis_instance.get(data))
                user_data.append(temp_user_info)

        elif self.request.query_params.get('account'):
            account_id = self.request.query_params.get('account')
            for data in redis_instance.scan_iter(f"User_*_{account_id}_*"):
                temp_user_info = json.loads(redis_instance.get(data))
                user_data.append(temp_user_info)

        elif self.request.query_params.get('team'):
            team_id = self.request.query_params.get('team')
            for data in redis_instance.scan_iter(f"User_*_*_{team_id}*"):
                temp_user_info = json.loads(redis_instance.get(data))
                user_data.append(temp_user_info)

        return user_data

    def get(self, request, *args, **kwargs):

        redis_instance = redis.StrictRedis(host=os.environ.get('INFRA_REDIS_CACHE_HOST', 'localhost'), port=6379,
                                           password=os.environ.get('INFRA_REDIS_CACHE_PASS', None),
                                           db=int(os.environ.get('INFRA_REDIS_CACHE_DB', 1)))
        user_data = list()

        if not self.request.query_params:
            for data in redis_instance.scan_iter("User*"):
                temp_user_info = json.loads(redis_instance.get(data))
                user_data.append(temp_user_info)

        elif "initiate_user_cache" in self.request.query_params.keys():
            tasks.cache_current_user_data.delay()
            return response.Response(messages.USER_DATA_CACHE_SCRIPT_INITIATED, status=status.HTTP_200_OK)

        elif "flush_user_cache" in self.request.query_params.keys():
            tasks.flush_user_cache.delay()
            return response.Response(messages.USER_DATA_CACHE_FLUSH_SCRIPT_INITIATED, status=status.HTTP_200_OK)

        elif any(item in self.request.query_params.keys() for item in ['team', 'id', 'account']):
            user_data = self.filter_user_data(redis_instance)
        else:
            return response.Response(messages.INVALID_USER_REDIS_API_FILTER_KEYS, status=status.HTTP_200_OK)

        return response.Response({"count": len(user_data),
                                  "data": user_data}, status=status.HTTP_200_OK)

