from datetime import datetime

from jwt import DecodeError
from rest_framework import authentication
from rest_framework import exceptions
import jwt

from rest_framework_securejwt.models import User
from rest_framework_securejwt.settings import api_settings


class JwtAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        # Get the access token
        auth_header = request.META.get('HTTP_AUTHORIZATION')
        if auth_header is None:
            raise exceptions.NotAuthenticated()

        # Check if the token sounds correct
        split_authorization = auth_header.split()
        if len(split_authorization) == 0 or len(split_authorization) > 2:
            raise exceptions.NotAuthenticated()

        # Get data from the token
        token = split_authorization[1]
        decoded_token = self.decode_access_token(token)

        # Check the expiration date
        self.check_expiration(decoded_token)

        # Get the user
        user = self.get_user(decoded_token)
        return user, token

    @staticmethod
    def decode_access_token(token):
        try:
            return jwt.decode(token, api_settings.SIGNING_KEY, algorithms=api_settings.ALGORITHM)
        except DecodeError:
            raise exceptions.NotAuthenticated()

    @staticmethod
    def check_expiration(decoded_token):
        exp = decoded_token[api_settings.EXP_CLAIM]
        date_now = datetime.now()
        exp_date = datetime.utcfromtimestamp(exp)

        if exp_date < date_now:
            raise exceptions.NotAuthenticated()

    @staticmethod
    def get_user(decoded_token):
        if decoded_token[api_settings.USER_ID_CLAIM] is None:
            raise exceptions.NotAuthenticated()

        user_id = decoded_token[api_settings.USER_ID_CLAIM]

        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise exceptions.NotAuthenticated()
