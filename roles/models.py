from django.db import models

# Create your models here.
class user_roles(models.Model):
    role_name = models.CharField(
        max_length=30,  blank=True, null=True, unique=True)
    role_description = models.CharField(max_length=100, blank=True)
    date_added = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.role_name

    class Meta:
        verbose_name = "User Role"
        verbose_name_plural = "User Roles"
        ordering = ['-date_added']