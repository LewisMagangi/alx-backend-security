import datetime
from django.utils import timezone
from django.core.cache import cache
from django.http import HttpResponseForbidden

from ip_tracking.models import RequestLog, BlockedIP

class IPTrackingMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        ip_address = self.get_client_ip(request)
        path = request.path

        # Check blacklist
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Access denied: your IP is blocked.")

    def __call__(self, request):
        ip_address = self.get_client_ip(request)
        path = request.path

        # Check blacklist
        if BlockedIP.objects.filter(ip_address=ip_address).exists():
            return HttpResponseForbidden("Access denied: your IP is blocked.")

        # Get geolocation info (with caching)
        cache_key = f"geo_{ip_address}"
        geo = cache.get(cache_key)
        if geo is None:
            # assume the django-ip-geolocation middleware has set request.geolocation
            geo_info = getattr(request, 'geolocation', None)
            if geo_info:
                country = geo_info.get('country_name') or geo_info.get('country')
                city = geo_info.get('city')
            else:
                country = None
                city = None

            geo = {
                'country': country,
                'city': city,
            }
            # cache for 24 hours (86400 seconds)
            cache.set(cache_key, geo, 86400)
        else:
            country = geo.get('country')
            city = geo.get('city')

        # Log request
        RequestLog.objects.create(
            ip_address=ip_address,
            path=path,
            country=country,
            city=city,
        )

        response = self.get_response(request)
        return response

    def get_client_ip(self, request):
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
