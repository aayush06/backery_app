from django.utils.deprecation import MiddlewareMixin
from django.conf import LazySettings


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
