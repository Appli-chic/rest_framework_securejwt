from datetime import timedelta

from django.conf import settings
from rest_framework.settings import APISettings
from django.test.signals import setting_changed

USER_SETTINGS = getattr(settings, 'JWT', None)

DEFAULTS = {
    'ACCESS_TOKEN_LIFETIME': timedelta(minutes=15),
    'ALGORITHM': 'HS256',
    'SIGNING_KEY': settings.SECRET_KEY,
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'id',
    'EXP_CLAIM': 'exp',
}

IMPORT_STRINGS = (
    'AUTH_TOKEN_CLASSES',
)


class JwtSettings(APISettings):
    def __check_user_settings(self, user_settings):
        return user_settings


api_settings = APISettings(USER_SETTINGS, DEFAULTS, IMPORT_STRINGS)


def reload_api_settings(*args, **kwargs):
    global api_settings

    setting, value = kwargs['setting'], kwargs['value']

    if setting == 'JWT':
        api_settings = APISettings(value, DEFAULTS, IMPORT_STRINGS)


setting_changed.connect(reload_api_settings)
