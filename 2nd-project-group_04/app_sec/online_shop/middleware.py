# myapp/middleware.py

from django.shortcuts import redirect
from django.urls import reverse

from online_shop import settings


class AuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # URLs protected behind 2FA with TOTP
        protected_urls = [
            reverse('orders:create_order'),
            reverse('accounts:edit_profile'),
            reverse('accounts:change_password')
        ]

        # delete session variables associated to OTP verification
        # when going to URLs that don't require OTP verification
        if request.path not in protected_urls and not request.path.startswith("/static"):
            if "valid_otp_accounts" in request.session:
                del request.session["valid_otp_accounts"]
            if "valid_otp_sensitive" in request.session:
                del request.session["valid_otp_sensitive"]
        return self.get_response(request)
