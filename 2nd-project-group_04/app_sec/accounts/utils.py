import requests
from cryptography.hazmat.primitives import hashes
from django.contrib import messages
from django.shortcuts import redirect

# takes in password and returns number of times it has been breached
# returning 0 means it has not been breached
# returns -1 for invalid request
def check_for_breach(password):
    digest = hashes.Hash(hashes.SHA1())
    digest.update(password.encode("utf-8"))
    password_hash = digest.finalize().hex().upper()

    prefix, suffix = password_hash[:5], password_hash[5:]

    # request passwords with given prefix from have i been pwned API
    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    res = requests.get(url=url, headers={"Add-Padding": "true"})
    if res.status_code == 200:  # OK
        # list of lists with [suffix, count] while also filtering out padded results
        pwned_passwords = [
            parts
            for line in res.text.splitlines()
            if (parts := line.split(":")) and parts[1] != "0"
        ]
        for hash_suffix, count in pwned_passwords:
            if suffix == hash_suffix:  # matched one of the breached passwords
                return count

        return 0
    return -1


def get_redirect_login(request):
    breach_count = request.session['haveBeenPwnd']
    # unsafe password - redirect user to change password with error message
    if breach_count != 0:
        messages.error(
            request, f'Password has been breached {breach_count} times. Please change it for your safety.',
            'danger'
        )
    return redirect('shop:home_page')

