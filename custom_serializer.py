"""
Base Serializer
"""
import os

from django.conf import settings
from django.contrib.auth.models import Permission
from logging_essar import init_logging
from rest_framework.exceptions import PermissionDenied
from rest_framework.fields import empty
from rest_framework.serializers import ModelSerializer
from rest_framework import serializers
import bleach
import re

PERMISSION_LOGS = init_logging(log_name='PERMISSION_LOGS', log_directory=os.path.join(settings.BASE_DIR, 'logs'),
                               enable_mailing=False, delay=1, rotation_criteria='time',
                               rotate_interval=1, rotate_when='midnight', backup_count=365)
IGNORE_FIELD_VALIDATION_IN_SERIALIZER = settings.__dict__['_wrapped'].__dict__['IGNORE_FIELD_VALIDATION_IN_SERIALIZER']


class BaseSerializer(ModelSerializer):
    """
    base serializer for models rbac
    """
    request_method_permission_codename_mapping = {
        "post": "add_{}",
        "patch": "change_{}",
        "put": "change_{}",
        "delete": "delete_{}",
        "get": "view_{}",
    }

    def __init__(self, instance=None, data=empty, request=None, **kwargs):
        super().__init__(instance, data, **kwargs)
        self.request = request
        if request and ('request_user' not in request \
                        or 'request_method' not in request \
                        or not self.is_authorized(request['request_user'], request['request_method'])):
            PERMISSION_LOGS.info(
                "Permission error {} for user {}".format(request['request_user'], request['request_method']))
            raise PermissionDenied()

    def is_authorized(self, request_user, request_method):
        """
        Checking if user has permissions to access this model
        Permission should be assigned to the user or to the assigned groups
        """
        request_method = request_method.lower()
        user_groups = request_user.groups.all()
        model_name = self.Meta.model.__name__.lower().replace(" ", "")
        if request_method not in self.request_method_permission_codename_mapping.keys():
            return True

        permission_codename = self.request_method_permission_codename_mapping[
            request_method].format(model_name)

        # Checking if user groups has permissions assigned or not
        for each in user_groups:
            if each.permissions.filter(codename=permission_codename).exists():
                return True
            else:
                miss_permission = Permission.objects.filter(codename=permission_codename).last()
                each.permissions.add(miss_permission)

        # Checking if user has direct permissions assigned
        if Permission.objects.filter(user__username=request_user.username,
                                     codename=permission_codename).exists():
            return True

        PERMISSION_LOGS.info("Permission error {} for user {}".format(permission_codename, request_user.username))
        return False


    def validate(self, data):
        """
        Validate and sanitize the entire payload.
        - Check for ASCII-only strings.
        - Convert empty strings to None.
        - Sanitize strings to prevent XSS.
        """
        errors = {}

        for field_name, value in self.initial_data.items():

            if field_name in IGNORE_FIELD_VALIDATION_IN_SERIALIZER:
                continue

            # Handle strings
            if isinstance(value, str):
                # Convert empty strings to None
                if value == "":
                    continue

                # Check for ASCII-only characters
                if not re.match(r'^[\x00-\x7F]*$', value):
                    errors[field_name] = "Field contains invalid characters."
                    continue

                # Sanitize to prevent XSS
                sanitized_value = bleach.clean(value,strip=True)
                if sanitized_value != value:
                    errors[field_name] = "Field contains invalid characters (e.g., HTML)."
                    continue

        if errors:
            raise serializers.ValidationError(errors)

        return data
