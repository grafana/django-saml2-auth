import pytest
from django_saml2_auth.user import *
from django.contrib.auth.models import Group


def trigger_change_first_name(user: Dict[str, Any]) -> None:
    user = get_user(user)
    user.first_name = "CHANGED_FIRSTNAME"
    user.save()


@pytest.mark.django_db
def test_create_new_user_success(settings):
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
def test_create_new_user_no_group_error(settings):
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
    with pytest.raises(SAMLAuthError) as exc_info:
        create_new_user("", "John", "Doe")

    assert str(exc_info.value) == "There was an error creating the new user."
    assert exc_info.value.extra["exc_type"] == ValueError


@pytest.mark.django_db
def test_get_or_create_user_success(settings):
    settings.SAML2_AUTH = {
        "ATTRIBUTES_MAP": {
            "groups": "groups",
        },
        "GROUPS_MAP": {
            "consumers": "users"
        }
    }

    Group.objects.create(name="users")
    created, user = get_or_create_user({
        "username": "test@example.com",
        "first_name": "John",
        "last_name": "Doe",
        "user_identity": {
            "user.username": "test@example.com",
            "user.first_name": "John",
            "user.last_name": "Doe",
            "groups": ["consumers"]
        }
    })
    assert created
    assert user.username == "test@example.com"
    assert user.is_active == True
    assert user.has_usable_password() == False
    assert user.groups.get(name="users") == Group.objects.get(name="users")


@pytest.mark.django_db
def test_get_or_create_user_trigger_error(settings):
    settings.SAML2_AUTH = {
        "TRIGGER": {
            "CREATE_USER": "django_saml2_auth.tests.test_user.nonexistent_trigger",
        }
    }

    with pytest.raises(SAMLAuthError) as exc_info:
        get_or_create_user({
            "username": "test@example.com",
            "first_name": "John",
            "last_name": "Doe"
        })

    assert str(exc_info.value) == (
        "module 'django_saml2_auth.tests.test_user' has no attribute 'nonexistent_trigger'")
    assert isinstance(exc_info.value.extra["exc"], AttributeError)


@pytest.mark.django_db
def test_get_or_create_user_trigger_change_first_name(settings):
    settings.SAML2_AUTH = {
        "TRIGGER": {
            "CREATE_USER": "django_saml2_auth.tests.test_user.trigger_change_first_name",
        }
    }

    created, user = get_or_create_user({
        "username": "test@example.com",
        "first_name": "John",
        "last_name": "Doe"
    })

    assert created
    assert user.username == "test@example.com"
    assert user.first_name == "CHANGED_FIRSTNAME"
    assert user.is_active == True
    assert user.has_usable_password() == False


@pytest.mark.django_db
def test_get_or_create_user_should_not_create_user(settings):
    settings.SAML2_AUTH = {
        "CREATE_USER": False,
    }

    with pytest.raises(SAMLAuthError) as exc_info:
        get_or_create_user({
            "username": "test@example.com",
            "first_name": "John",
            "last_name": "Doe"
        })

    assert str(exc_info.value) == "Cannot create user."
    assert exc_info.value.extra["reason"] == (
        "Due to current config, a new user should not be created.")


def test_get_user_id_success():
    assert get_user_id({"username": "test@example.com"}) == "test@example.com"
    assert get_user_id("test@example.com") == "test@example.com"


@pytest.mark.django_db
def test_get_user_success():
    create_new_user("test@example.com", "John", "Doe")
    user_1 = get_user({"username": "test@example.com"})
    user_2 = get_user("test@example.com")

    assert user_1.username == "test@example.com"
    assert user_2.username == "test@example.com"
    assert user_1 == user_2


def test_create_jwt_token_success():
    jwt_token = create_jwt_token("test@example.com")
    assert isinstance(jwt_token, str)
    assert "." in jwt_token
    assert jwt_token.count(".") == 2


def test_create_jwt_token_no_secret_no_algorithm(settings):
    settings.SAML2_AUTH = {
        "JWT_SECRET": None,
        "JWT_ALGORITHM": None
    }

    with pytest.raises(SAMLAuthError) as exc_info:
        create_jwt_token("test@example.com")

    assert str(exc_info.value) == "Cannot create JWT token. Specify secret and algorithm."


def test_decode_jwt_token_success():
    jwt_token = create_jwt_token("test@example.com")
    user_id = decode_jwt_token(jwt_token)

    assert user_id == "test@example.com"


def test_decode_jwt_token_failure():
    with pytest.raises(SAMLAuthError) as exc_info:
        decode_jwt_token(None)

    assert str(exc_info.value) == "Cannot decode JWT token."
    assert isinstance(exc_info.value.extra["exc"], PyJWTError)
