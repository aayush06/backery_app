from rest_framework import permissions


class AdminOnly(permissions.BasePermission):

    def has_permission(self, request, view):
        if request.user.is_bakery_admin:
            return True
        else:
            return False
