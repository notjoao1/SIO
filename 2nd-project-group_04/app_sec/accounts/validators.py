
from django.core.exceptions import ValidationError
import requests
from cryptography.hazmat.primitives import hashes
from .utils import check_for_breach

# according to ASVS 2.1 password strength requirements
def validate_password(value):
    if len(value) < 12:
        raise ValidationError("Password must be at least 12 characters long.")

    if len(value) > 128:
        raise ValidationError("Password must be, at most, 128 characters long.")

# takes in password, hashes using SHA-1, and checks against pwned passwords API
# with header 'Add-Padding' : true, for extra security
# more info here: https://haveibeenpwned.com/API/v3#SearchingPwnedPasswordsByRange
def validate_breached_password(password):
    count = check_for_breach(password)
    if count != 0:
        raise ValidationError(f"Password has been breached {count} times.")

def validate_match_password(value, confirm_value):
    if value != confirm_value:
        raise ValidationError("Passwords do not match.")
    
# guarantee that new password is different from current password
def validate_new_password_diff(new_password, current_password):
    if new_password == current_password:
        raise ValidationError("New password must differ from current password.")


def validate_email_length(value):
    if len(value) > 100:
        raise ValidationError("Email must be at most 100 characters long.")
    
    
def validate_full_name_length(value):
    if len(value) > 100:
        raise ValidationError("Full name must be at most 100 characters long.")