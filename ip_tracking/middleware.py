from datetime import datetime
from .models import RequestLog

class IPTrackingMiddleware:
    """
    Middleware to log IP address, timestamp, and path for each request.
    """
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Get IP address
        ip_address = self.get_client_ip(request)
        path = request.path

        # Save request log
        RequestLog.objects.create(ip_address=ip_address, path=path)

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        """Extract the client's IP address safely."""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
