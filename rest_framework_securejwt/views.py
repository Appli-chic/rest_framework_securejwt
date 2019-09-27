from datetime import datetime
from django.contrib.auth import authenticate
from django.db import transaction
from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed, ParseError
from rest_framework.permissions import AllowAny
from rest_framework.response import Response
from rest_framework.views import APIView
import jwt

from rest_framework_securejwt.models import RefreshToken, User
from rest_framework_securejwt.serializers import RefreshSerializer, RegisterSerializer, LoginSerializer
from rest_framework_securejwt.settings import api_settings

CODE_EMAIL_EXISTS = "email_exists"
CODE_USERNAME_EXISTS = "username_exists"


def create_access_token(user_id):
    date = datetime.now() + api_settings.ACCESS_TOKEN_LIFETIME
    return jwt.encode(
        {
            api_settings.USER_ID_CLAIM: user_id,
            api_settings.EXP_CLAIM: date
        },
        api_settings.SIGNING_KEY,
        algorithm=api_settings.ALGORITHM
    )


class Refresh(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    serializer_class = RefreshSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        # Retrieve the user
        refresh_token = data['refresh_token']
        user = User.get_user_with_refresh_token(refresh_token)

        # Create a new access token
        access_token = create_access_token(user.id)

        return Response({
            'access_token': access_token,
            'exp': api_settings.ACCESS_TOKEN_LIFETIME.total_seconds(),
        }, status=status.HTTP_201_CREATED)


class Register(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    serializer_class = RegisterSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        return self.create_user(serializer.validated_data)

    @staticmethod
    def create_user(data):
        username = data['username']
        password = data['password']
        email = data['email']

        # Check if email or name already exist
        if User.get_user_with_email_exists(email):
            raise ParseError({
                'message': 'Email already exists',
                'code': CODE_EMAIL_EXISTS
            })

        if User.user_with_username_exists(username):
            raise ParseError({
                'message': 'Username already exists',
                'code': CODE_USERNAME_EXISTS
            })

        # Create the user
        with transaction.atomic():
            user = User.create_user(username, email, password)
            user.save()

            token = RefreshToken.create_token(user.id)
            token.save()

        access_token = create_access_token(user.id)

        return Response({
            'refresh_token': token.value,
            'access_token': access_token,
            'exp': api_settings.ACCESS_TOKEN_LIFETIME.total_seconds(),
        }, status=status.HTTP_201_CREATED)


class Login(APIView):
    authentication_classes = []
    permission_classes = [AllowAny]
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Login the user
        username = serializer.validated_data['username']
        password = serializer.validated_data['password']
        user = authenticate(username=username, password=password)

        if user is not None:
            # Create the access token
            access_token = create_access_token(user.id)
            refresh_token = RefreshToken.get_token_with_user_id(user.id).value

            return Response({
                'refresh_token': refresh_token,
                'access_token': access_token,
                'exp': api_settings.ACCESS_TOKEN_LIFETIME.total_seconds(),
            }, status=status.HTTP_200_OK)
        else:
            raise AuthenticationFailed()
