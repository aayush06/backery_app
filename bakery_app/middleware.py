from django.utils.deprecation import MiddlewareMixin
from django.conf import LazySettings
from django.http import JsonResponse

from authorization.models import AppVersion

settings = LazySettings()


class RequestCheckMiddleware(MiddlewareMixin):
    """
        This middleware will check for site-id in request header
    """

    def process_request(self, request):
        if any(map(request.path.__contains__, ["media", "static"])):
            return
        if request.path == '/':
            return
        if 'HTTP_IMEI' in request.META.keys():
            request.is_android_app = True
            request.imei = request.META.get('HTTP_IMEI', None)
            if not request.imei:
                request.imei = 'Demo'
        else:
            request.is_android_app = False
            request.imei = None

        if request.is_android_app:
            request.version = request.META.get('HTTP_VERSION', None)
            version = AppVersion.objects.last()
            if 'HTTP_VERSION' not in request.META.keys() or request.version not in version.app_version:
                return JsonResponse({'error': 'A new version of the Waynaq App is available in the Playstore. Please '
                                              'download the new application from Playstore in order to continue using'
                                              ' the Waynaq App.',
                                     'non_field_errors': [
                                         'A new version of the Waynaq App is available in the Playstore. Please '
                                         'download the new application from Playstore in order to continue using the '
                                         'Waynaq App.']},
                                    status=485)

        site_id = request.META.get('HTTP_SITE_ID', None)
        if site_id:
            request.site_id = site_id
            return
        else:
            return JsonResponse(
                {'error': 'SITE-ID required in request header'},
                status=400
            )
