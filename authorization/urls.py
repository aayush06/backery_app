from django.conf.urls import url, include

from rest_framework.routers import DefaultRouter

from . import apis

router = DefaultRouter()
router.register(r"permission", apis.PermissionViewSet, base_name="permission")
router.register(r"role", apis.RoleViewSet, base_name="role")
router.register('app-version', apis.AppVersionViewset, base_name='app-version')
router.register(r"user", apis.UserViewSet, base_name="user")
router.register(r"test-user", apis.TestUserViewSet, base_name="test-user")
router.register(r"user-list", apis.UserReadViewSet, base_name="user-list")
router.register(r"admin-reset-password", apis.AdminResetPassword,
                base_name="admin-reset-password")
router.register(r"shift-team-detail", apis.TeamDetailViewSet,
                base_name="shift-team-detail")
router.register(r"all-user-list", apis.UserOpenViewSet,
                base_name="all-user-list")
router.register(r"open-api-create-user", apis.OpenAPIUserCreate,
                base_name="open-api-create-user")
router.register(r"throttling-list", apis.ListThrottlingModel,
                base_name="throttling-list")
router.register(r"all-role-list", apis.RoleOpenViewSet,
                base_name="all-role-list")

urlpatterns = [
    url(r'^', include(router.urls)),
    url(r'^register/$', apis.UserRegistrationView.as_view(),
        name="user-registration"),
    url(r'^login/$', apis.LoginView.as_view(), name="user-login"),
    url(r'^open-api-auth/$', apis.OpenAPIAuthentication.as_view(),
        name="open-api-auth"),
    url(r'^forgot-password/$', apis.ForgotPasswordAPIView.as_view(),
        name="forgot-password"),
    url(r'^verify-otp/$', apis.UserVerifyOtp.as_view(), name="verify-otp"),
    url(r'^verify-otp-reset-password/$',
        apis.OtpVerifyPasswordResetAPIView.as_view(),
        name="verify-otp-reset-password"),
    url(r'^change-password/$', apis.ChangePasswordView.as_view(),
        name="change-password"),
    url(r'^reset-password/$', apis.PasswordResetView.as_view(),
        name="reset-password"),
    url(r'^resend-otp/$', apis.ResendOtp.as_view(),
        name="resend-otp"),
    url(r'^me/$', apis.MyAccountView.as_view(),
        name="my-profile"),
    url(r'user-alert-prefernces', apis.UserAlertPreferenceViewSet.as_view(),
        name='user-alert-prefernces'),
    url(r'get-user-manager-email/', apis.GetUserStoreManagerEmail.as_view(),
        name='get-user-manager-email'),
    url(r'multiple-user-team-delete/', apis.MultipleTeamUserDeleteAPIView.as_view(),
        name='multiple-user-team-delete'),
    url(r'model-export/$', apis.ExportAPIView.as_view(),
        name='model-export'),
    url(r'model-download/$', apis.DownloadAPIView.as_view(),
        name='model-download'),
    url(r'user-upload/$', apis.UserUploadAPIView.as_view(),
        name='user-upload'),
    url(r'role-upload/$', apis.RoleUploadAPIView.as_view(),
        name='role-upload'),
    url(r'team-upload/$', apis.TeamUploadAPIView.as_view(),
        name='team-upload'),
    url(r'team-upload-update/$', apis.TeamUploadUpdateAPIView.as_view(),
        name='team-upload'),
    url(r'user-export/$', apis.UserExportAPIView.as_view(),
        name='user-export'),
    url(r'role-export/$', apis.RoleExportAPIView.as_view(),
        name='role-export'),
    url(r'^requested-extracts/$',
        apis.RequestedDownloadView.as_view()),
    url(r'^user-by-teams/$',
        apis.UsersByTeamView.as_view()),
    url(r'^dump-off-day/$',
        apis.MarkUserCurrentMonthOffDay.as_view()),
    url(r'^get-throttling-status/$',
        apis.GetThrottlingLimit.as_view()),
    url(r'^user_cache/$', apis.RedisView.as_view(),
        name="user-cache"),
]
