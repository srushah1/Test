from django.conf import settings
from django.contrib import admin
from django.urls import path, include

PROJECT_URL = settings.__dict__['_wrapped'].__dict__['PROJECT_API_PREFIX']
urlpatterns = [
    # path(PROJECT_URL + '/admin/', admin.site.urls),
    path(PROJECT_URL + '/', include('custom_admin.urls')),
    path(PROJECT_URL + '/', include('api.urls')),
    path(PROJECT_URL + '/tax_request/', include('tax_request.urls')),
    path(PROJECT_URL + '/workflow/', include('workflow.urls')),
    path(PROJECT_URL + '/masters/', include('masters.urls')),
]
