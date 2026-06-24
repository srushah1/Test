from django.contrib.auth.models import Permission
from rest_framework import permissions

from masters.logger_directory import BASE_SERIALIZER_LOGS


class IsAuthorized(permissions.BasePermission):

    def has_permission(self, request, view):
        """
        Checking if user has permissions to access this viewset
        Permission should be assigned to the user or to the assigned groups
        Example:
            get_customerdetails_view
            post_customerregistration_view
            put_customerupdate_view
            delete_customerfile_view
        """
        view_name = view.__class__.__name__.lower()
        request_method = request.method.lower()
        permission_codename = request_method + "_" + view_name + "_view"

        user = request.user
        user_groups = user.groups.all()
        BASE_SERIALIZER_LOGS.info('[%s] REQUESTED VIEW LEVEL [%s] PERMISSION ', format(request.user.username),
                                  format(permission_codename))

        # Checking if user groups has permissions assigned or not
        for each in user_groups:
            if each.permissions.filter(codename=permission_codename).exists():
                return True

        # Checking if user has direct permissions assigned
        if Permission.objects.filter(user__username=user.username, codename=permission_codename).exists():
            return True
        BASE_SERIALIZER_LOGS.info(
            'User [%s] is_denied FOR VIEW LEVEL [%s] PERMISSION ', format(request.user.username),
            format(permission_codename))
        return False
