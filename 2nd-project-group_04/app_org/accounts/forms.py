from django import forms
from django.core.exceptions import ValidationError

from .models import User


class UserLoginForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(
            attrs={'class': 'form-control', 'placeholder': 'email'}
        )
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={'class': 'form-control', 'placeholder': 'password'}
        )
    )


class UserRegistrationForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(
            attrs={'class': 'form-control', 'placeholder': 'email'}
        )
    )
    full_name = forms.CharField(
        widget=forms.TextInput(
            attrs={'class': 'form-control', 'placeholder': 'full name'}
        )
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={'class': 'form-control', 'placeholder': 'password'}
        )
    )

    def clean(self):
        cleaned_data = super().clean()
        email = cleaned_data.get('email')
        username = cleaned_data.get('full_name')
        password = cleaned_data.get('password')

        validate_password(password, email, username)

        return cleaned_data



class ManagerLoginForm(forms.Form):
    email = forms.EmailField(
        widget=forms.EmailInput(
            attrs={'class': 'form-control', 'placeholder': 'email'}
        )
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={'class': 'form-control', 'placeholder': 'password'}
        )
    )


class EditProfileForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ['full_name', 'email']


def validate_password(value, email, username):
    if len(value) < 8:
        raise ValidationError("Password must be at least 8 characters long.")

    if not any(char in r'!@#$%^&*()+[]{}|;:,.<>?/`~' for char in value):
        raise ValidationError("Password must contain at least one special character.")

    if not any(char.isdigit() for char in value):
        raise ValidationError("Password must contain at least one number.")

    if not any(char.isupper() for char in value):
        raise ValidationError("Password must contain at least one uppercase letter.")

    if not any(char.islower() for char in value):
        raise ValidationError("Password must contain at least one lowercase letter.")

    email_prefix = email.split('@')[0]
    if email_prefix in value:
        raise ValidationError("Password cannot contain the part of your email.")

    if username in value:
        raise ValidationError("Password cannot contain a substring of your username.")