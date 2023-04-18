from datetime import datetime

from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models


class UserManager(BaseUserManager):
    def create_user(self, login, password=None, authorities=False, email=None):
        if not login:
            raise ValueError("Users must have a login")

        user = self.model(
            login=login,
            email=self.normalize_email(email),
            authorities=authorities,
        )

        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, login, password, authorities=True, email=None):
        user = self.create_user(
            login=login,
            password=password,
            email=email,
            authorities=True,
        )
        user.is_admin = True
        user.save(using=self._db)
        return user


class User(AbstractBaseUser, PermissionsMixin):
    login = models.CharField(max_length=30, unique=True)
    email = models.EmailField(unique=True)
    authorities = models.IntegerField(default=1)
    last_login = models.DateTimeField(default=datetime.now)

    USERNAME_FIELD = 'login'
    REQUIRED_FIELDS = ['email', 'authorities']
    primary_key = 'login'

    objects = UserManager()

    class Meta:
        db_table = 'Users_cal'

    @property
    def is_staff(self):
        return self.authorities

    @property
    def is_superuser(self):
        return self.authorities

    @property
    def is_active(self):
        return True

    def has_perm(self, perm, obj=None):
        return True

    def has_module_perms(self, app_label):
        return True

    def get_full_name(self):
        return self.login

    def get_short_name(self):
        return self.login

    def check_password(self, raw_password):
        return raw_password == self.password

    def __str__(self):
        return self.login

