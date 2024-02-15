from accounts.models import User
user = User.objects.all().filter(email="manager@example.com")
if user:
    user[0].delete()

