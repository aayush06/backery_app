from django.conf.urls import url

from . import apis

urlpatterns = [
    url(r'^backery-admin-register/$', apis.BackeryAdminRegistrationView.as_view(),
        name="backery-admin-registration"),
    url(r'^register/$', apis.UserRegistrationView.as_view(),
        name="customer-register"),
    url(r'^login/$', apis.LoginView.as_view(), name="user-login"),
]
