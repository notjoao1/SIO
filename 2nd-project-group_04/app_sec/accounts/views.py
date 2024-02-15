from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, logout
from django.contrib.auth import login as auth_login

from online_shop.decorators import no_auth_required, my_login_required, verified_required, not_verified_required
from .forms import UserRegistrationForm, UserLoginForm, ManagerLoginForm, EditProfileForm, ChangePasswordForm, \
    MyOTPTokenForm
from django.db.utils import IntegrityError
from accounts.models import User
from .utils import check_for_breach, get_redirect_login
from django.views.decorators.cache import never_cache
from django_ratelimit.decorators import ratelimit
from django_otp import login as otp_login
from django_otp.plugins.otp_totp.models import TOTPDevice
import qrcode
from io import BytesIO
from base64 import b64encode
import os
from django.conf import settings	

@never_cache
@not_verified_required
def manager_login(request):
    if request.method == 'POST':
        form = ManagerLoginForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            user = authenticate(
                request, email=data['email'], password=data['password']
            )
            if user is not None and user.is_manager:
                # user "logged in" - still requires 2FA to be verified and access the rest of the webapp
                auth_login(request, user)
                request.session.set_expiry(120)
                request.session['haveBeenPwnd'] = check_for_breach(data['password'])
                return redirect('accounts:user_login_2s')
            else:
                messages.error(
                    request, 'Email or password is invalid.', 'danger'
                )
                return redirect('accounts:manager_login')
    else:
        form = ManagerLoginForm()
    context = {'form': form}
    return render(request, 'manager_login.html', context)

@never_cache
@ratelimit(key='ip', rate='15/m', block=True)
@not_verified_required
def user_register(request):
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            try:
                user = User.objects.create_user(
                    data['email'], data['full_name'], data['password']
                )
                return redirect('accounts:user_login')
            except IntegrityError:
                # broad message
                messages.error(
                    request, 'Email is invalid.', 'danger'
                )
    else:
        form = UserRegistrationForm()
    context = {'title': 'Signup', 'form': form}
    return render(request, 'register.html', context)

@never_cache
@ratelimit(key='ip', rate='15/m', block=True)
@not_verified_required
def user_login(request):
    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            data = form.cleaned_data
            user = authenticate(
                request, email=data['email'], password=data['password']
            )
            if user is not None:
                # user "logged in" - still requires 2FA to be verified and access the rest of the webapp
                auth_login(request, user)
                request.session.set_expiry(120)
                request.session['haveBeenPwnd'] = check_for_breach(data['password'])
                return redirect('accounts:user_login_2s')
                # unsafe password - redirect user to change password with error message
            else:
                messages.error(
                    request, 'Email or password is invalid.', 'danger'
                )
    else:
        form = UserLoginForm()
    context = {'title': 'Login', 'form': form}
    return render(request, 'login.html', context)

@never_cache
@my_login_required
def otp_view(request):
    context = {}
    if request.method == "POST":
        form = MyOTPTokenForm(user=request.user, data=request.POST)
        if form.is_valid():
            # user proves that has the secret key when validates a token for the first time
            # device -> confirmed
            device = TOTPDevice.objects.get(user=request.user)
            device.confirmed = True
            device.save()
            otp_login(request, device)
            request.session.set_expiry(settings.SESSION_COOKIE_AGE)
            return get_redirect_login(request)
    else:
        form = MyOTPTokenForm(user=request.user)
    # only 1 device per user
    device = TOTPDevice.objects.get(user=request.user)
    if not device.confirmed:
        qr_code_img = qrcode.make(device.config_url)
        buffer = BytesIO()
        qr_code_img.save(buffer)
        buffer.seek(0)
        encoded_img = b64encode(buffer.read()).decode()
        qr_code_data = f'data:image/png;base64,{encoded_img}'
        context['qr_code_data'] = qr_code_data
    context['form'] = form
    return render(request, 'login2s.html', context)

@never_cache
@verified_required
def otp_view_verify(request):
    context = {}
    if request.method == "POST":
        form = MyOTPTokenForm(user=request.user, data=request.POST)
        if form.is_valid():
            redirect_to = request.session.get("redirect_to")
            if redirect_to.startswith("accounts:"):
                request.session["valid_otp_accounts"] = True
            else:
                request.session["valid_otp_sensitive"] = True
            request.session["valid_otp"] = True
            del request.session["redirect_to"]
            return redirect(redirect_to)
    else:
        form = MyOTPTokenForm(user=request.user)
    context['form'] = form
    return render(request, 'login2s.html', context)

@never_cache
@verified_required
def user_logout(request):
    logout(request)
    return redirect('accounts:user_login')


@never_cache
@ratelimit(key='ip', rate='10/m', block=True)
@verified_required
def edit_profile(request):
    if request.session.get("valid_otp_accounts") != True:
        request.session["redirect_to"] = "accounts:edit_profile"
        return redirect('accounts:reauth_2s')
    form = EditProfileForm(request.POST, instance=request.user)
    user = User.objects.get(id=request.user.id)
    context = {'title': 'Edit Profile'}
    if form.is_valid():
        cleaned_data = form.cleaned_data
        if cleaned_data["full_name"] != user.full_name or cleaned_data["email"] != user.email:
            del request.session["valid_otp_accounts"]
            form.save()
            messages.success(request, 'Your profile has been updated', 'success')
            return redirect('shop:home_page')
    else:
        form = EditProfileForm(instance=request.user)
    context["form"] = form
    return render(request, 'edit_profile.html', context)


@never_cache
@ratelimit(key='ip', rate='10/m', block=True)
@verified_required
def change_password(request):
    if request.session.get("valid_otp_accounts") != True:
        request.session["redirect_to"] = "accounts:change_password"
        return redirect('accounts:reauth_2s')
    if request.method == "POST":
        form = ChangePasswordForm(request.POST)
        if form.is_valid():
            user = request.user
            data = form.cleaned_data
            if not request.user or not authenticate(request, email=user.email, password=data.get("current_password")):
                messages.error(
                    request, "Current password doesn't match.", "danger"
                )
                context = {"title": "Change Password", "form": form}
                return render(request, "change_password.html", context)

            user.set_password(data.get("new_password"))
            user.save()
            messages.success(request, "Your password has been successfully updated", "success")
            del request.session["valid_otp_accounts"]
            return redirect("accounts:change_password")
    else:
        form = ChangePasswordForm()

    context = {"title": "Change Password", "form": form}
    return render(request, "change_password.html", context)

@never_cache
@ratelimit(key='ip', rate='10/m', block=True)
@verified_required
def delete_account(request):
    reviews = request.user.review_set.all()
    for review in reviews:        
        if review.user_review_image:    
            review.user_review_image.delete()
    orders = request.user.orders.all()
    for order in orders:
        order_id = order.id
        file_name = f"{order_id}.txt"
        file_path = os.path.join(settings.MEDIA_ROOT, "invoices", file_name)
        if os.path.exists(file_path):
            os.remove(file_path)

    request.user.delete()
    messages.success(request, "Your account has been successfully deleted", "success")
    return redirect("accounts:user_login")
    
   
