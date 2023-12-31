from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.hashers import make_password

class UserManager(BaseUserManager):
    def create_user(self,email, password=None, **extra_fields):
        if not email:
            raise ValueError("Email is required")
        email=self.normalize_email(email)
        user=self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self.db)
        return user

    def create_superuser(self,email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff',True)
        extra_fields.setdefault('is_superuser',True)
        extra_fields.setdefault('is_active',True)
        return self.create_user(email, password, **extra_fields)
    
# class SellerManager(BaseUserManager):
#     def create_seller(self,email, password=None, **extra_fields):
#         if not email:
#             raise ValueError("Email is required")
#         email=self.normalize_email(email)
#         user=self.model(email=email, **extra_fields)
#         user.make_password(password)
#         user.save(using=self.db)
#         return user