from django.shortcuts import render
from django.http import HttpResponse
from django_ratelimit.decorators import ratelimit

def rate_function(group, request):
    """
    Custom rate function to apply different limits based on authentication status.
    Returns rate limit string: '10/m' for authenticated, '5/m' for anonymous.
    """
    if request.user.is_authenticated:
        return '10/m'  # 10 requests per minute for authenticated users
    return '5/m'  # 5 requests per minute for anonymous users

@ratelimit(key='ip', rate=rate_function, method=['GET', 'POST'], block=True)
def login_view(request):
    """
    Login view with rate limiting:
    - Authenticated users: 10 requests/minute
    - Anonymous users: 5 requests/minute
    """
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        return HttpResponse(f"Attempted login as {username}")
    return HttpResponse("Login page (POST to attempt login)")
