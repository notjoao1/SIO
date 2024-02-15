from django import forms
from django_otp.plugins.otp_totp.models import TOTPDevice
from .validators import validate_password, validate_match_password, validate_new_password_diff, validate_breached_password,  validate_email_length, validate_full_name_length
from django_otp.forms import OTPTokenForm
from .models import User
from django.forms.widgets import HiddenInput

class UserLoginForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={"class": "form-control", "placeholder": "email"}),
        max_length=100,
        validators=[validate_email_length]
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control",
                "placeholder": "password",
                "id": "passwordInput",
            }
        )
    )


class UserRegistrationForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={"class": "form-control", "placeholder": "email"}),
        max_length=100,
        validators=[validate_email_length]
    )
    full_name = forms.CharField(
        widget=forms.TextInput(
            attrs={"class": "form-control", "placeholder": "full name"}
        ),
        max_length=100,
        validators=[validate_full_name_length]
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={"class": "form-control", "placeholder": "password", "id": "passwordInput"},
        ),
        validators=[validate_password, validate_breached_password]
    )


class ManagerLoginForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={"class": "form-control", "placeholder": "email"}),
        max_length=100,
        validators=[validate_email_length]
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={"class": "form-control", "placeholder": "password", "id": "passwordInput"}
        )
    )


class EditProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ["full_name", "email"]

class ChangePasswordForm(forms.Form):
    current_password = forms.CharField(
        widget=forms.PasswordInput(attrs={"class": "form-control", "placeholder": "current password"})
    )
    new_password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={"class": "form-control", "placeholder": "new password", "id": "passwordInput"},
        ),
        validators=[validate_password, validate_breached_password]
    )
    confirm_new_password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={"class": "form-control", "placeholder": "new password", "id": "confirmPasswordInput"},
        ),
        validators=[validate_password, validate_breached_password]
    )

    def clean(self):
        cleaned_data = super().clean()

        validate_match_password(cleaned_data.get("new_password"), cleaned_data.get("confirm_new_password"))

        validate_new_password_diff(cleaned_data.get("new_password"), cleaned_data.get("current_password"))


class MyOTPTokenForm(OTPTokenForm):
    # otp error messages from OTPTokenForm are fine
    # no need to make custom error messages

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if not self.fields['otp_device'].choices:
            # if device doesn't exist it is created automatically with confirmed=false (only 1 device per user)
            # confirmed=false until the user later uses it to validate a TOTP token (proving he/she has the secret key)
            # The idea is to prevent locking a user out of the account if he generates a secret key but fails the setup
            device, created = TOTPDevice.objects.get_or_create(user=self.user, name="1st TOTP Device", confirmed=False)
            self.fields['otp_device'].choices = [(f"otp_totp.totpdevice/{device.id}", device.name)]

        # Set default value for device (the one device that exists per user)
        self.fields['otp_device'].initial = self.fields['otp_device'].choices[0][0]
        # Modify labels
        self.fields['otp_device'].label = 'Chose Your Device'
        self.fields['otp_token'].label = 'Enter the Verification Code'
        # Hide device because there is only one per user
        self.fields['otp_device'].widget = HiddenInput()
        # remove challenge attribute
        del self.fields['otp_challenge']

