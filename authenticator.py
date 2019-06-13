import datetime
from _blake2 import blake2b

from rest_framework import exceptions
from rest_framework.authentication import BaseAuthentication, get_authorization_header
from rest_framework.settings import api_settings

ACCEPTABLE_TIME_DIFF = 5  # seconds


def get_secret(api_key: str, nonce: str, secret_key: str):
    h = blake2b(digest_size=64)
    h.update(api_key.encode('utf-8'))
    h.update(nonce.encode('utf-8'))
    h.update(secret_key.encode('utf-8'))
    return h.hexdigest()


def validate_api_key(api_key: str):
    from .apps import API_KEY_LENGTH
    if type(api_key) is not str or len(api_key) != API_KEY_LENGTH:
        return

    return True


def validate_nonce(nonce: str):
    if type(nonce) is not str or not nonce.isdigit() or len(nonce) != 10:
        return

    if abs(int(nonce) - int(datetime.datetime.now().timestamp())) > ACCEPTABLE_TIME_DIFF:
        return

    return True


class SecurestRequestsAuthenticator:
    def __init__(self, api_key, secret_key):
        self.api_key = api_key
        self.secret_key = secret_key

    def __call__(self, request):
        nonce = str(int(datetime.datetime.now().timestamp()))
        auth = 'securest {} {} {}'.format(self.api_key, nonce, get_secret(self.api_key, nonce, self.secret_key))
        request.headers['Authorization'] = auth
        return request


class SecurestRestFrameworkAuthentication(BaseAuthentication):
    """
    Use Securest Token for authentication.
    """

    def authenticate(self, request):
        """
        Returns a `User` if the request contain valid securest token.
        Otherwise returns `None`.
        """
        from .models import SecurestToken

        auth = get_authorization_header(request).split()
        if not auth or auth[0].lower() != b'securest':
            return None

        if len(auth) != 4:
            raise exceptions.AuthenticationFailed('Invalid securest header. Arguments length is not valid.')

        auth_type, api_key, nonce, secret = [a.decode() for a in auth]
        token = SecurestToken.objects.filter(api_key=api_key).first()

        if not validate_api_key(api_key):
            raise exceptions.AuthenticationFailed('Invalid securest header. API Key is not valid.')

        if not validate_nonce(nonce):
            raise exceptions.AuthenticationFailed('Invalid securest header. Nonce is not valid.')

        try:
            assert token
            assert secret == get_secret(api_key, nonce, token.secret_key)
        except:
            raise exceptions.AuthenticationFailed('Invalid securest header. Some arguments value is not valid.')

        return (token.user, None)


def get_default_authentication_classes_with_securest():
    return api_settings.DEFAULT_AUTHENTICATION_CLASSES + [SecurestRestFrameworkAuthentication]
