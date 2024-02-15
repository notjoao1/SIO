from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth.decorators import user_passes_test

WRAPPED_BY_AUTH = "is_wrapped_by_auth"


def no_access(
        function=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None
):
    """
    Decorator that denies access to all views by default.
    This decorator will delegate authentication to the following decorators if they are specified:
    - no_auth_required
    - my_login_required
    - verified_required
    - not_verified_required
    - manager_required
    """
    if function:
        # print(getattr(function, WRAPPED_BY_AUTH, False))
        actual_decorator = user_passes_test(
            lambda u: getattr(function, WRAPPED_BY_AUTH, False),
            login_url=login_url,
            redirect_field_name=redirect_field_name,
        )
        return actual_decorator(function)

    actual_decorator = user_passes_test(
        lambda u: False,
        login_url=login_url,
        redirect_field_name=redirect_field_name,
    )
    return actual_decorator


def no_auth_required(
        function=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None
):
    """
    Decorator that allows any user (anonymous, "logged in" or verified) to access the view
    """
    actual_decorator = user_passes_test(
        lambda u: True,
        login_url=login_url,
        redirect_field_name=redirect_field_name,
    )
    if function:
        setattr(function, WRAPPED_BY_AUTH, True)
        return actual_decorator(function)
    return actual_decorator


def my_login_required(
        function=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None
):
    """
    Decorator for views that checks that the user is "logged in" (without 2FA - without being verified), redirecting
    to the log-in page if necessary.
    Already verified users cannot access the views marked with my_login_required.
    Actually the only view marked with my_login_required is otp_view() and we don't want verified users accessing it
    because it resets the session cookie expiry.
    """
    actual_decorator = user_passes_test(
        lambda u: u.is_authenticated and not u.is_verified(),
        login_url=login_url,
        redirect_field_name=redirect_field_name,
    )
    if function:
        setattr(function, WRAPPED_BY_AUTH, True)
        return actual_decorator(function)
    return actual_decorator


def verified_required(
        function=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None
):
    """
    Decorator for views that checks that the user is verified (logged in with credentials + TOTP auth), redirecting
    to the log-in page if necessary.
    """
    actual_decorator = user_passes_test(
        lambda u: u.is_verified(),
        login_url=login_url,
        redirect_field_name=redirect_field_name,
    )
    if function:
        setattr(function, WRAPPED_BY_AUTH, True)
        return actual_decorator(function)
    return actual_decorator


def not_verified_required(
        function=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None
):
    """
    Decorator for views that checks if the user isn't verified (either not logged in with credentials or no TOTP auth),
    redirecting to the log-in page if necessary.
    """
    actual_decorator = user_passes_test(
        lambda u: not u.is_verified(),
        login_url=login_url,
        redirect_field_name=redirect_field_name,
    )
    if function:
        setattr(function, WRAPPED_BY_AUTH, True)
        return actual_decorator(function)
    return actual_decorator


def manager_required(
        function=None, redirect_field_name=REDIRECT_FIELD_NAME, login_url=None
):
    """
    Decorator for views that checks that the user is logged in and that it is a manager redirecting
    to the log-in page if necessary.
    """
    actual_decorator = user_passes_test(
        lambda u: u.is_verified() and u.is_manager,
        login_url=login_url,
        redirect_field_name=redirect_field_name,
    )
    if function:
        setattr(function, WRAPPED_BY_AUTH, True)
        return actual_decorator(function)
    return actual_decorator
