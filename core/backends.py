from django.contrib.auth.models import User, check_password
from models import SocialAuth

class EmailAuthBackend(object):
    """
    Email Authentication Backend
    Allows a user to sign in using an email/password pair rather than
    a username/password pair.
    """
    def authenticate(self, username=None, password=None):
        """ Authenticate a user based on email address as the user name. """
        try:
            user = User.objects.get(email=username)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        """ Get a User object from the user_id. """
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return

class IdAuthBackend(object):
    """
    Id Authentication Backend
    Allows a user to sign in using an user id/password pair rather than
    a username/password pair.
    """
    def authenticate(self, username=None, password=None):
        """ Authenticate a user based on email address as the user name. """
        try:
            user = User.objects.get(id=username)
            if user.check_password(password):
                return user
        except User.DoesNotExist:
            return None

    def get_user(self, user_id):
        """ Get a User object from the user_id. """
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return

class SocialAuthBackend(object):
    """
    Social Authentication Backend
    Allows a user to sign in using an email/provider/provider_id pair rather than
    a username/password pair.
    """
    def authenticate(self, username=None, provider=None, provider_id=None):
        if SocialAuth.actives.filter(user__email=username).filter(provider_id=provider_id).filter(provider=provider).exists():
            try:
                user = User.objects.get(email=username)
                return user
            except User.DoesNotExist:
                return None
        else:
            return None

    def get_user(self, user_id):
        """ Get a User object from the user_id. """
        try:
            return User.objects.get(pk=user_id)
        except User.DoesNotExist:
            return