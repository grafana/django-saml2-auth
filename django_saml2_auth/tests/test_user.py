from typing import Any, Dict

import mock
import pytest
from django.contrib.auth.models import Group, UserManager
from django.contrib.auth import get_user_model
from django_saml2_auth.exceptions import SAMLAuthError
from django_saml2_auth.user import (create_jwt_token, create_new_user,
                                    decode_jwt_token, get_or_create_user,
                                    get_user, get_user_id)
from jwt.exceptions import PyJWTError
from pytest_django.fixtures import SettingsWrapper


User = get_user_model()


class MyUserManager(UserManager):
    def create_user_with_email_username(self, email, password=None, **extra_fields):
        """
        Required for django-saml2-auth integration.
        """
        if email == '':
            raise ValueError('invalid email')
        password = password or ''
        return super().create(username=email, email=email, password=password, **extra_fields)


def has_usable_password(self):
    if not self.password:
        return False
    return is_password_usable(self.password)


User.add_to_class('objects', MyUserManager())
User.add_to_class('has_usable_password', has_usable_password)


def trigger_change_first_name(request, user: Dict[str, Any], target_user, extra_fields) -> None:
    """Trigger function to change user's first name.

    Args:
        user (Dict[str, Any]): User information
    """
    user = get_user(user)
    user.first_name = "CHANGED_FIRSTNAME"
    user.save()


@pytest.mark.django_db
def test_create_new_user_success(settings: SettingsWrapper):
    """Test create_new_user function to verify if it works and correctly joins the user to the
    respective group.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH = {
        "NEW_USER_PROFILE": {
            "USER_GROUPS": ["users"],
        }
    }

    # Create a group for the users to join
    Group.objects.create(name="users")
    user = create_new_user("test@example.com", "John", "Doe")
    # It can also be email depending on USERNAME_FIELD setting
    assert user.username == "test@example.com"
    assert user.is_active == True
    assert user.has_usable_password() == False
    assert user.groups.get(name="users") == Group.objects.get(name="users")


@pytest.mark.django_db
def test_create_new_user_no_group_error(settings: SettingsWrapper):
    """Test create_new_user function to verify if it creates the user, but fails to join the user
    to the respective group.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH = {
        "NEW_USER_PROFILE": {
            "USER_GROUPS": ["users"],
        }
    }

    with pytest.raises(SAMLAuthError) as exc_info:
        create_new_user("test@example.com", "John", "Doe")

    assert str(exc_info.value) == "There was an error joining the user to the group."
    assert exc_info.value.extra["exc_type"] == Group.DoesNotExist


def test_create_new_user_value_error():
    """Test create_new_user function to verify if it raises an exception upon passing invalid value
    as user_id."""
    with pytest.raises(SAMLAuthError) as exc_info:
        create_new_user("", "John", "Doe")

    assert str(exc_info.value) == "There was an error creating the new user."
    assert exc_info.value.extra["exc_type"] == ValueError


@pytest.mark.django_db
def test_get_or_create_user_success(settings: SettingsWrapper):
    """Test get_or_create_user function to verify if it creates a new user and joins it to the
    correct group based on the given SAML group and its mapping with internal groups.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH = {
        "ATTRIBUTES_MAP": {
            "groups": "groups",
        },
        "GROUPS_MAP": {
            "consumers": "users"
        }
    }

    Group.objects.create(name="users")
    request = mock.Mock()
    created, user = get_or_create_user(request, {
        "username": "test@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "user_identity": {
            "user.username": "test@example.com",
            "user.first_name": "John",
            "user.last_name": "Doe",
            "groups": ["consumers"]
        }
    }, None)
    assert created
    assert user.username == "test@example.com"
    assert user.is_active == True
    assert user.has_usable_password() == False
    assert user.groups.get(name="users") == Group.objects.get(name="users")


@pytest.mark.django_db
def test_get_or_create_user_trigger_error(settings: SettingsWrapper):
    """Test get_or_create_user function to verify if it raises an exception in case the CREATE_USER
    trigger function is nonexistent.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH = {
        "TRIGGER": {
            "CREATE_USER": "django_saml2_auth.tests.test_user.nonexistent_trigger",
        }
    }

    request = mock.Mock()
    with pytest.raises(SAMLAuthError) as exc_info:
        get_or_create_user(request, {
            "username": "test@example.com",
            "first_name": "John",
            "last_name": "Doe"
        }, None)

    assert str(exc_info.value) == (
        "module 'django_saml2_auth.tests.test_user' has no attribute 'nonexistent_trigger'")
    assert isinstance(exc_info.value.extra["exc"], AttributeError)


@pytest.mark.django_db
def test_get_or_create_user_trigger_change_first_name(settings: SettingsWrapper):
    """Test get_or_create_user function to verify if it correctly triggers the CREATE_USER function
    and the trigger updates the user's first name.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH = {
        "TRIGGER": {
            "CREATE_USER": "django_saml2_auth.tests.test_user.trigger_change_first_name",
        }
    }

    request = mock.Mock()
    created, user = get_or_create_user(request, {
        "username": "test@example.com",
        "first_name": "John",
        "last_name": "Doe"
    }, None)

    assert created
    assert user.username == "test@example.com"
    assert user.first_name == "CHANGED_FIRSTNAME"
    assert user.is_active == True
    assert user.has_usable_password() == False


@pytest.mark.django_db
def test_get_or_create_user_should_not_create_user(settings: SettingsWrapper):
    """Test get_or_create_user function to verify if it raise an exception while creating a new user
    is prohibited by settings.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH = {
        "CREATE_USER": False,
    }

    request = mock.Mock()
    with pytest.raises(SAMLAuthError) as exc_info:
        get_or_create_user(request, {
            "username": "test@example.com",
            "first_name": "John",
            "last_name": "Doe"
        }, None)

    assert str(exc_info.value) == "Cannot create user."
    assert exc_info.value.extra["reason"] == (
        "Due to current config, a new user should not be created.")


def test_get_user_id_success():
    """Test get_user_id function to verify if it correctly returns the user_id based on the
    User.USERNAME_FIELD."""
    assert get_user_id({"username": "test@example.com"}) == "test@example.com"
    assert get_user_id("test@example.com") == "test@example.com"


@pytest.mark.django_db
def test_get_user_success():
    """Test get_user function by first creating a new user and then trying to fetch it."""
    create_new_user("test@example.com", "John", "Doe")
    user_1 = get_user({"username": "test@example.com"})
    user_2 = get_user("test@example.com")

    assert user_1.username == "test@example.com"
    assert user_2.username == "test@example.com"
    assert user_1 == user_2


def test_create_jwt_token_success():
    """Test create_jwt_token function to verify JWT token generation."""
    jwt_token = create_jwt_token("test@example.com")
    assert isinstance(jwt_token, str)
    assert "." in jwt_token
    assert jwt_token.count(".") == 2


def test_create_jwt_token_no_secret_no_algorithm(settings: SettingsWrapper):
    """Test create_jwt_token function by trying to create a JWT token with no secret and algorithm
    set.

    Args:
        settings (SettingsWrapper): Fixture for django settings
    """
    settings.SAML2_AUTH = {
        "JWT_SECRET": None,
        "JWT_ALGORITHM": None
    }

    with pytest.raises(SAMLAuthError) as exc_info:
        create_jwt_token("test@example.com")

    assert str(exc_info.value) == "Cannot create JWT token. Specify secret and algorithm."


def test_decode_jwt_token_success():
    """Test decode_jwt_token function by verifying if the newly created JWT token using
    create_jwt_token function is valid."""
    jwt_token = create_jwt_token("test@example.com")
    user_id, _ = decode_jwt_token(jwt_token)

    assert user_id == "test@example.com"


def test_decode_jwt_token_success_extra_data():
    """Test decode_jwt_token function by verifying if the newly created JWT token using
    create_jwt_token function is valid."""
    jwt_token = create_jwt_token("test@example.com", foo='bar', baz='bam')
    user_id, extra_data = decode_jwt_token(jwt_token)

    assert user_id == "test@example.com"
    assert extra_data == {"foo": "bar", "baz": "bam", "username": "test@example.com"}


def test_decode_jwt_token_failure():
    """Test decode_jwt_token function by passing an invalid JWT token (None, in this case)."""
    with pytest.raises(SAMLAuthError) as exc_info:
        decode_jwt_token(None)

    assert str(exc_info.value) == "Cannot decode JWT token."
    assert isinstance(exc_info.value.extra["exc"], PyJWTError)
