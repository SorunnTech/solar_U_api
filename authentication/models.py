from django.db import models
from django.contrib.auth.models import AbstractUser
from roles.models import user_roles

# Create your models here.
class CustomUser(AbstractUser):
    phone_number = models.CharField(
        max_length=20, blank=True, null=True, unique=True)
    role = models.ForeignKey(user_roles, on_delete=models.CASCADE,  null=True)
    otp = models.CharField(blank=True, max_length=7)
    otp_expiry = models.DateTimeField(null=True,blank=True)
    password_reset_link_expiry = models.DateTimeField(null=True,blank=True)

    def __str__(self):
        return self.email