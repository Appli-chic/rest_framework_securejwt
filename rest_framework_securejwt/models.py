from django.contrib.auth.models import AbstractUser
from django.db import models
import uuid


class User(AbstractUser):
    @classmethod
    def create_user(cls, username, email=None, password=None):
        new_user = cls.objects.create_user(username, email=email, password=password)
        return new_user

    @classmethod
    def get_user_with_email_exists(cls, user_email):
        return User.objects.filter(email=user_email).exists()

    @classmethod
    def user_with_username_exists(cls, username):
        return User.objects.filter(username=username).exists()

    @classmethod
    def get_user_with_refresh_token(cls, refresh_token):
        return User.objects.get(refreshtoken__value=refresh_token)


class RefreshToken(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='refreshtoken', null=False, blank=False)
    value = models.TextField('value', unique=True, null=False, blank=False)

    @classmethod
    def create_token(cls, user_id):
        return cls.objects.create(user_id=user_id, value=str(uuid.uuid4()))

    @classmethod
    def get_token_with_user_id(cls, user_id):
        return RefreshToken.objects.get(user_id=user_id)
