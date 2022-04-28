"""Utility functions for getting or creating user accounts
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple, Union

import jwt
from cryptography.hazmat.primitives import serialization
from dictor import dictor  # type: ignore
from django import get_version
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group, User
from django_saml2_auth.errors import (CANNOT_DECODE_JWT_TOKEN,
                                      CREATE_USER_ERROR, GROUP_JOIN_ERROR,
                                      INVALID_JWT_ALGORITHM, NO_JWT_ALGORITHM,
                                      NO_JWT_PRIVATE_KEY, NO_JWT_PUBLIC_KEY,
                                      NO_JWT_SECRET, NO_USER_ID,
                                      SHOULD_NOT_CREATE_USER)
from django_saml2_auth.exceptions import SAMLAuthError
from django_saml2_auth.utils import run_hook
from jwt.algorithms import (get_default_algorithms, has_crypto,
                            requires_cryptography)
from jwt.exceptions import PyJWTError
from pkg_resources import parse_version


def create_new_user(email: str, firstname: str, lastname: str) -> User:
    """Create a new user with the given information

    Args:
        email (str): Email
        firstname (str): First name
        lastname (str): Last name

    Raises:
        SAMLAuthError: There was an error creating the new user.
        SAMLAuthError: There was an error joining the user to the group.

    Returns:
        User: Returns a new user object, usually a subclass of the the User model
    """
    saml2_auth_settings = settings.SAML2_AUTH
    user_model = get_user_model()

    is_active = dictor(saml2_auth_settings, "NEW_USER_PROFILE.ACTIVE_STATUS", default=True)
    is_staff = dictor(saml2_auth_settings, "NEW_USER_PROFILE.STAFF_STATUS", default=False)
    is_superuser = dictor(saml2_auth_settings, "NEW_USER_PROFILE.SUPERUSER_STATUS", default=False)
    user_groups = dictor(saml2_auth_settings, "NEW_USER_PROFILE.USER_GROUPS", default=[])

    try:
        user = user_model.objects.create_user(email, first_name=firstname, last_name=lastname)
        user.is_active = is_active
        user.is_staff = is_staff
        user.is_superuser = is_superuser
        user.save()
    except Exception as exc:
        raise SAMLAuthError("There was an error creating the new user.", extra={
            "exc": exc,
            "exc_type": type(exc),
            "error_code": CREATE_USER_ERROR,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })

    try:
        groups = [Group.objects.get(name=group) for group in user_groups]
        if groups:
            if parse_version(get_version()) <= parse_version("1.8"):
                user.groups = groups
            else:
                user.groups.set(groups)
    except Exception as exc:
        raise SAMLAuthError("There was an error joining the user to the group.", extra={
            "exc": exc,
            "exc_type": type(exc),
            "error_code": GROUP_JOIN_ERROR,
            "reason": "There was an error processing your request.",
            "status_code": 500
        })

    user.save()
    user.refresh_from_db()

    return user


def get_or_create_user(user: Dict[str, Any]) -> Tuple[bool, User]:
    """Get or create a new user and optionally add it to one or more group(s)

    Args:
        user (Dict[str, Any]): User information

    Raises:
        SAMLAuthError: Cannot create user. Missing user_id.
        SAMLAuthError: Cannot create user.

    Returns:
        Tuple[bool, User]: A tuple containing user creation status and user object
    """
    saml2_auth_settings = settings.SAML2_AUTH
    user_model = get_user_model()
    created = False

    try:
        target_user = get_user(user)
    except user_model.DoesNotExist:
        should_create_new_user = dictor(saml2_auth_settings, "CREATE_USER", True)
        if should_create_new_user:
            user_id = get_user_id(user)
            if not user_id:
                raise SAMLAuthError("Cannot create user. Missing user_id.", extra={
                    "error_code": SHOULD_NOT_CREATE_USER,
                    "reason": "Cannot create user. Missing user_id.",
                    "status_code": 400
                })
            target_user = create_new_user(user_id, user["first_name"], user["last_name"])

            create_user_trigger = dictor(saml2_auth_settings, "TRIGGER.CREATE_USER")
            if create_user_trigger:
                run_hook(create_user_trigger, user)  # type: ignore

            target_user.refresh_from_db()
            created = True
        else:
            raise SAMLAuthError("Cannot create user.", extra={
                "exc_type": Exception,
                "error_code": SHOULD_NOT_CREATE_USER,
                "reason": "Due to current config, a new user should not be created.",
                "status_code": 500
            })

    # Optionally update this user's group assignments by updating group memberships from SAML groups
    # to Django equivalents
    group_attribute = dictor(saml2_auth_settings, "ATTRIBUTES_MAP.groups")
    group_map = dictor(saml2_auth_settings, "GROUPS_MAP")

    if group_attribute and group_attribute in user["user_identity"]:
        groups = []

        for group_name in user["user_identity"][group_attribute]:
            # Group names can optionally be mapped to different names in Django
            if group_map and group_name in group_map:
                group_name_django = group_map[group_name]
            else:
                group_name_django = group_name

            try:
                groups.append(Group.objects.get(name=group_name_django))
            except Group.DoesNotExist:
                pass

        if parse_version(get_version()) >= parse_version("2.0"):
            target_user.groups.set(groups)
        else:
            target_user.groups = groups

    return (created, target_user)


def get_user_id(user: Union[str, Dict[str, Any]]) -> Optional[str]:
    """Get user_id (username or email) from user object

    Args:
        user (Union[str, Dict[str, Any]]): A cleaned user info object

    Returns:
        Optional[str]: user_id, which is either email or username
    """
    user_model = get_user_model()
    user_id = None

    if isinstance(user, dict):
        user_id = user["email"] if user_model.USERNAME_FIELD == "email" else user["username"]

    if isinstance(user, str):
        user_id = user

    return user_id.lower() if user_id else None


def get_user(user: Union[str, Dict[str, str]]) -> User:
    """Get user from database given a cleaned user info object or a user_id

    Args:
        user (Union[str, Dict[str, str]]): Either a user_id (as str) or a cleaned user info object

    Returns:
        User: An instance of the User model
    """
    saml2_auth_settings = settings.SAML2_AUTH
    user_model = get_user_model()
    user_id = get_user_id(user)

    # Should email be case-sensitive or not. Default is False (case-insensitive).
    login_case_sensitive = dictor(saml2_auth_settings, "LOGIN_CASE_SENSITIVE", False)
    id_field = (
        user_model.USERNAME_FIELD
        if login_case_sensitive
        else f"{user_model.USERNAME_FIELD}__iexact")
    return user_model.objects.get(**{id_field: user_id})


def validate_jwt_algorithm(jwt_algorithm: str) -> None:
    """Validate JWT algorithm

    Args:
        jwt_algorithm (str): JWT algorithm

    Raises:
        SAMLAuthError: Cannot encode/decode JWT token. Specify an algorithm.
        SAMLAuthError: Cannot encode/decode JWT token. Specify a valid algorithm.
    """
    if not jwt_algorithm:
        raise SAMLAuthError("Cannot encode/decode JWT token. Specify an algorithm.", extra={
            "exc_type": Exception,
            "error_code": NO_JWT_ALGORITHM,
            "reason": "Cannot create JWT token for login.",
            "status_code": 500
        })

    if jwt_algorithm not in list(get_default_algorithms()):
        raise SAMLAuthError("Cannot encode/decode JWT token. Specify a valid algorithm.", extra={
            "exc_type": Exception,
            "error_code": INVALID_JWT_ALGORITHM,
            "reason": "Cannot encode/decode JWT token for login.",
            "status_code": 500
        })


def validate_secret(jwt_algorithm: str, jwt_secret: str) -> None:
    """Validate symmetric encryption key

    Args:
        jwt_algorithm (str): JWT algorithm
        jwt_secret (str): JWT secret

    Raises:
        SAMLAuthError: Cannot encode/decode JWT token. Specify a secret.
    """
    if jwt_algorithm not in requires_cryptography and not jwt_secret:
        raise SAMLAuthError("Cannot encode/decode JWT token. Specify a secret.", extra={
            "exc_type": Exception,
            "error_code": NO_JWT_SECRET,
            "reason": "Cannot encode/decode JWT token for login.",
            "status_code": 500
        })


def validate_private_key(jwt_algorithm: str, jwt_private_key: str) -> None:
    """Validate private key

    Args:
        jwt_algorithm (str): JWT algorithm
        jwt_private_key (str): JWT private key

    Raises:
        SAMLAuthError: Cannot encode/decode JWT token. Specify a private key.
    """
    if (jwt_algorithm in requires_cryptography and has_crypto) and not jwt_private_key:
        raise SAMLAuthError("Cannot encode/decode JWT token. Specify a private key.", extra={
            "exc_type": Exception,
            "error_code": NO_JWT_PRIVATE_KEY,
            "reason": "Cannot encode/decode JWT token for login.",
            "status_code": 500
        })


def validate_public_key(jwt_algorithm: str, jwt_public_key: str) -> None:
    """Validate public key

    Args:
        jwt_algorithm (str): JWT algorithm
        jwt_public_key (str): JWT public key

    Raises:
        SAMLAuthError: Cannot encode/decode JWT token. Specify a public key.
    """
    if (jwt_algorithm in requires_cryptography and has_crypto) and not jwt_public_key:
        raise SAMLAuthError("Cannot encode/decode JWT token. Specify a public key.", extra={
            "exc_type": Exception,
            "error_code": NO_JWT_PUBLIC_KEY,
            "reason": "Cannot encode/decode JWT token for login.",
            "status_code": 500
        })


def create_jwt_token(user_id: str) -> Optional[str]:
    """Create a new JWT token

    Args:
        user_id (str): User's username or email based on User.USERNAME_FIELD

    Returns:
        Optional[str]: JWT token
    """
    saml2_auth_settings = settings.SAML2_AUTH
    user_model = get_user_model()

    jwt_algorithm = dictor(saml2_auth_settings, "JWT_ALGORITHM")
    validate_jwt_algorithm(jwt_algorithm)

    jwt_secret = dictor(saml2_auth_settings, "JWT_SECRET")
    validate_secret(jwt_algorithm, jwt_secret)

    jwt_private_key = dictor(saml2_auth_settings, "JWT_PRIVATE_KEY")
    validate_private_key(jwt_algorithm, jwt_private_key)

    jwt_private_key_passphrase = dictor(saml2_auth_settings, "JWT_PRIVATE_KEY_PASSPHRASE")
    jwt_expiration = dictor(saml2_auth_settings, "JWT_EXP", 60)  # default: 1 minute

    payload = {
        user_model.USERNAME_FIELD: user_id,
        "exp": (datetime.now(tz=timezone.utc) +
                timedelta(seconds=jwt_expiration)).timestamp()
    }

    # If a passphrase is specified, we need to use a PEM-encoded private key
    # to decrypt the private key in order to encode the JWT token.
    if jwt_private_key_passphrase:
        if isinstance(jwt_private_key, str):
            jwt_private_key = jwt_private_key.encode()
        if isinstance(jwt_private_key_passphrase, str):
            jwt_private_key_passphrase = jwt_private_key_passphrase.encode()

        # load_pem_private_key requires data and password to be in bytes
        jwt_private_key = serialization.load_pem_private_key(
            data=jwt_private_key,
            password=jwt_private_key_passphrase
        )

    secret = jwt_secret if (
        jwt_secret and
        jwt_algorithm not in requires_cryptography) else jwt_private_key

    return jwt.encode(payload, secret, algorithm=jwt_algorithm)


def create_custom_or_default_jwt(user: Union[str, User]):
    """Create a new JWT token, eventually using custom trigger

    Args:
        user (Union[str, User]): User instance or User's username or email
            based on User.USERNAME_FIELD

    Raises:
        SAMLAuthError: Cannot create JWT token. Specify a user.

    Returns:
        Optional[str]: JWT token
    """
    saml2_auth_settings = settings.SAML2_AUTH
    user_model = get_user_model()

    custom_create_jwt_trigger = dictor(saml2_auth_settings, "TRIGGER.CUSTOM_CREATE_JWT")

    # If user is the id (user_model.USERNAME_FIELD), set it as user_id
    user_id: Optional[str] = None
    if isinstance(user, str):
        user_id = user

    # Check if there is a custom trigger for creating the JWT and URL query
    if custom_create_jwt_trigger:
        target_user = user
        # If user is user_id, get user instance
        if user_id:
            user_model = get_user_model()
            _user = {
                user_model.USERNAME_FIELD: user_id
            }
            target_user = get_user(_user)
        jwt_token = run_hook(custom_create_jwt_trigger, target_user)  # type: ignore
    else:
        # If user_id is not set, retrieve it from user instance
        if not user_id:
            user_id = getattr(user, user_model.USERNAME_FIELD)
        # Create a new JWT token with PyJWT
        if not user_id:
            raise SAMLAuthError("Cannot create JWT token. Specify a user.", extra={
                "exc_type": Exception,
                "error_code": NO_USER_ID,
                "reason": "Cannot create JWT token for login.",
                "status_code": 500
            })
        jwt_token = create_jwt_token(user_id)

    return jwt_token


def decode_jwt_token(jwt_token: str) -> Optional[str]:
    """Decode a JWT token

    Args:
        jwt_token (str): The token to decode

    Raises:
        SAMLAuthError: Cannot decode JWT token.

    Returns:
        Optional[str]: A user_id as str or None.
    """
    saml2_auth_settings = settings.SAML2_AUTH

    jwt_algorithm = dictor(saml2_auth_settings, "JWT_ALGORITHM")
    validate_jwt_algorithm(jwt_algorithm)

    jwt_secret = dictor(saml2_auth_settings, "JWT_SECRET")
    validate_secret(jwt_algorithm, jwt_secret)

    jwt_public_key = dictor(saml2_auth_settings, "JWT_PUBLIC_KEY")
    validate_public_key(jwt_algorithm, jwt_public_key)

    secret = jwt_secret if (
        jwt_secret and
        jwt_algorithm not in requires_cryptography) else jwt_public_key

    try:
        data = jwt.decode(jwt_token, secret, algorithms=jwt_algorithm)
        user_model = get_user_model()
        return data[user_model.USERNAME_FIELD]
    except PyJWTError as exc:
        raise SAMLAuthError("Cannot decode JWT token.", extra={
            "exc": exc,
            "exc_type": type(exc),
            "error_code": CANNOT_DECODE_JWT_TOKEN,
            "reason": "Cannot decode JWT token.",
            "status_code": 500
        })


def decode_custom_or_default_jwt(jwt_token: str) -> Optional[str]:
    """Decode a JWT token, eventually using custom trigger

    Args:
        jwt_token (str): The token to decode

    Raises:
        SAMLAuthError: Cannot decode JWT token.

    Returns:
        Optional[str]: A user_id as str or None.
    """
    saml2_auth_settings = settings.SAML2_AUTH
    custom_decode_jwt_trigger = dictor(saml2_auth_settings, "TRIGGER.CUSTOM_DECODE_JWT")
    if custom_decode_jwt_trigger:
        user_id = run_hook(custom_decode_jwt_trigger, jwt_token)  # type: ignore
    else:
        user_id = decode_jwt_token(jwt_token)
    return user_id
