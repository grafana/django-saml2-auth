#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""Endpoints for SAML SSO login"""

import urllib.parse as urlparse
import logging
from typing import Optional, Union
from urllib.parse import unquote

from dictor import dictor  # type: ignore
from django.conf import settings
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from django.template import TemplateDoesNotExist

try:
    from django.utils.http import \
        url_has_allowed_host_and_scheme as is_safe_url
except ImportError:
    from django.utils.http import is_safe_url

from django.views.decorators.csrf import csrf_exempt
from django_saml2_auth.errors import (INACTIVE_USER, INVALID_NEXT_URL,
                                      INVALID_REQUEST_METHOD, INVALID_TOKEN,
                                      USER_MISMATCH, BEFORE_LOGIN_TRIGGER_FAILURE)
from django_saml2_auth.exceptions import SAMLAuthError
from django_saml2_auth.saml import (decode_saml_response,
                                    extract_user_identity, get_assertion_url,
                                    get_default_next_url, get_saml_client)
from django_saml2_auth.user import (create_custom_or_default_jwt,
                                    decode_custom_or_default_jwt,
                                    get_or_create_user, get_user_id)
from django_saml2_auth.utils import (exception_handler, get_reverse,
                                     is_jwt_well_formed, run_hook)


logger = logging.getLogger(__name__)


@login_required
def welcome(request: HttpRequest) -> Union[HttpResponse, HttpResponseRedirect]:
    """Default welcome page

    Args:
        request (HttpRequest): Django request object.

    Returns:
        Union[HttpResponse, HttpResponseRedirect]: Django response or redirect object.
    """
    try:
        return render(request, "django_saml2_auth/welcome.html", {"user": request.user})
    except TemplateDoesNotExist:
        default_next_url = get_default_next_url()
        return (HttpResponseRedirect(default_next_url)
                if default_next_url
                else HttpResponseRedirect("/"))


def denied(request: HttpRequest) -> HttpResponse:
    """Default access denied page

    Args:
        request (HttpRequest): Django request object.

    Returns:
        HttpResponse: Render access denied page.
    """
    return render(request, "django_saml2_auth/denied.html")


@csrf_exempt
@exception_handler
def acs(request: HttpRequest):
    """Assertion Consumer Service is SAML terminology for the location at a ServiceProvider that
    accepts <samlp:Response> messages (or SAML artifacts) for the purpose of establishing a session
    based on an assertion. Assertion is a signed authentication request from identity provider (IdP)
    to acs endpoint.

    Args:
        request (HttpRequest): Incoming request from identity provider (IdP) for authentication

    Exceptions:
        SAMLAuthError: The target user is inactive.

    Returns:
        HttpResponseRedirect: Redirect to various endpoints: denied, welcome or next_url (e.g.
            the front-end app)

    Notes:
        https://wiki.shibboleth.net/confluence/display/CONCEPT/AssertionConsumerService
    """
    saml2_auth_settings = settings.SAML2_AUTH

    authn_response = decode_saml_response(request, acs)
    # decode_saml_response() will raise SAMLAuthError if the response is invalid,
    # so we can safely ignore the type check here.
    user = extract_user_identity(authn_response.get_identity())  # type: ignore

    next_url = request.session.get("login_next_url")
    extra_data = None

    # A RelayState is an HTTP parameter that can be included as part of the SAML request
    # and SAML response; usually is meant to be an opaque identifier that is passed back
    # without any modification or inspection, and it is used to specify additional information
    # to the SP or the IdP.
    # If RelayState params is passed, it could be JWT token that identifies the user trying to
    # login via sp_initiated_login endpoint, or it could be a URL used for redirection.
    relay_state = request.POST.get("RelayState")
    relay_state_is_token = is_jwt_well_formed(relay_state) if relay_state else False
    if next_url is None and relay_state and not relay_state_is_token:
        next_url = relay_state
    elif next_url is None:
        next_url = get_default_next_url()

    if relay_state and relay_state_is_token:
        redirected_user_id, extra_data = decode_custom_or_default_jwt(relay_state)

        # This prevents users from entering an email on the SP, but use a different email on IdP
        logger.debug('get_user_id vs redirected_user_id: %s %s', get_user_id(user), redirected_user_id)

        check_user_id = dictor(settings.SAML2_AUTH, "ASSERT_SP_VERSUS_IDP_USER_ID", default=True)
        if check_user_id and get_user_id(user) != redirected_user_id:
            raise SAMLAuthError("The user identifier doesn't match.", extra={
                "exc_type": ValueError,
                "error_code": USER_MISMATCH,
                "reason": "User identifier mismatch.",
                "status_code": 403
            })

    logger.debug('trying to get or create user')
    is_new_user, target_user = get_or_create_user(request, user, extra_data)

    logger.debug('get_or_create_user %s %s', is_new_user, target_user)

    get_next_url_trigger = dictor(settings.SAML2_AUTH, "TRIGGER.GET_NEXT_URL")
    if get_next_url_trigger:
        logger.debug('running next url trigger')
        next_url = run_hook(get_next_url_trigger, target_user, extra_data)

    logger.debug('next url %s', next_url)

    before_login_trigger = dictor(saml2_auth_settings, "TRIGGER.BEFORE_LOGIN")
    if before_login_trigger:
        hook_value = run_hook(before_login_trigger, request, user, target_user, is_new_user, extra_data)
        if hook_value is False:
            raise SAMLAuthError("The before login trigger returned False.", extra={
                "exc_type": ValueError,
                "error_code": BEFORE_LOGIN_TRIGGER_FAILURE,
                "reason": "Before login trigger returned False.",
                "status_code": 403
            })
        elif isinstance(hook_value, HttpResponseRedirect):
            # allow to redirect to some informative page
            return hook_value

    request.session.flush()

    use_jwt = dictor(saml2_auth_settings, "USE_JWT", False)
    if use_jwt and target_user.is_active:
        # Create a new JWT token for IdP-initiated login (acs)
        jwt_token = create_custom_or_default_jwt(target_user)
        custom_token_query_trigger = dictor(saml2_auth_settings, "TRIGGER.CUSTOM_TOKEN_QUERY")
        if custom_token_query_trigger:
            query = run_hook(custom_token_query_trigger, jwt_token)
        else:
            query = f"?token={jwt_token}"

        # Use JWT auth to send token to frontend
        frontend_url = dictor(saml2_auth_settings, "FRONTEND_URL", next_url)

        return HttpResponseRedirect(frontend_url + query)

    if target_user.is_active:
        # Try to load from the `AUTHENTICATION_BACKENDS` setting in settings.py
        if hasattr(settings, "AUTHENTICATION_BACKENDS") and settings.AUTHENTICATION_BACKENDS:
            model_backend = settings.AUTHENTICATION_BACKENDS[0]
        else:
            model_backend = "django.contrib.auth.backends.ModelBackend"

        login(request, target_user, model_backend)

        after_login_trigger = dictor(saml2_auth_settings, "TRIGGER.AFTER_LOGIN")
        if after_login_trigger:
            run_hook(after_login_trigger, request, user, target_user, extra_data)
            logger.warning('request session %s', dict(request.session))
    else:
        raise SAMLAuthError("The target user is inactive.", extra={
            "exc_type": Exception,
            "error_code": INACTIVE_USER,
            "reason": "User is inactive.",
            "status_code": 500
        })

    def redirect(redirect_url: Optional[str] = None) -> HttpResponseRedirect:
        """Redirect to the redirect_url or the root page.

        Args:
            redirect_url (str, optional): Redirect URL. Defaults to None.

        Returns:
            HttpResponseRedirect: Redirect to the redirect_url or the root page.
        """
        if redirect_url:
            return HttpResponseRedirect(redirect_url)
        else:
            return HttpResponseRedirect("/")

    if is_new_user:
        try:
            return render(request, "django_saml2_auth/welcome.html", {"user": request.user})
        except TemplateDoesNotExist:
            return redirect(next_url)
    else:
        return redirect(next_url)


@exception_handler
def sp_initiated_login(request: HttpRequest) -> HttpResponseRedirect:
    """This view is called by the SP to initiate a login to IdP, aka. SP-initiated SAML SSP.

    Args:
        request (HttpRequest): Incoming request from service provider (SP) for authentication

    Returns:
        HttpResponseRedirect: Redirect to the IdP login endpoint
    """
    # User must be created first by the IdP-initiated SSO (acs)
    if request.method == "GET":
        token = request.GET.get("token")
        if token:
            user_id, extra_data = decode_custom_or_default_jwt(token)
            if not user_id:
                raise SAMLAuthError("The token is invalid.", extra={
                    "exc_type": ValueError,
                    "error_code": INVALID_TOKEN,
                    "reason": "The token is invalid.",
                    "status_code": 403
                })
            saml_client = get_saml_client(get_assertion_url(request), acs, request, user_id, **extra_data)
            jwt_token = create_custom_or_default_jwt(user_id, **extra_data)
            logger.debug('Created JWT token with extra data %s for user_id %s', extra_data, user_id)
            _, info = saml_client.prepare_for_authenticate(  # type: ignore
                sign=False, relay_state=jwt_token)
            redirect_url = dict(info["headers"]).get("Location", "")
            if not redirect_url:
                return HttpResponseRedirect(
                    get_reverse([denied, "denied", "django_saml2_auth:denied"]))  # type: ignore
            return HttpResponseRedirect(redirect_url)
    else:
        raise SAMLAuthError("Request method is not supported.", extra={
            "exc_type": Exception,
            "error_code": INVALID_REQUEST_METHOD,
            "reason": "Request method is not supported.",
            "status_code": 404
        })
    return HttpResponseRedirect(
        get_reverse([denied, "denied", "django_saml2_auth:denied"]))  # type: ignore


@exception_handler
def signin(request: HttpRequest) -> HttpResponseRedirect:
    """Custom sign-in view for SP-initiated SSO. This will be deprecated in the future
    in favor of sp_initiated_login.

    Args:
        request (HttpRequest): Incoming request from service provider (SP) for authentication.

    Raises:
        SAMLAuthError: The next URL is invalid.

    Returns:
        HttpResponseRedirect: Redirect to the IdP login endpoint
    """
    saml2_auth_settings = settings.SAML2_AUTH

    next_url = request.GET.get("next") or get_default_next_url()
    if not next_url:
        raise SAMLAuthError("The next URL is invalid.", extra={
            "exc_type": ValueError,
            "error_code": INVALID_NEXT_URL,
            "reason": "The next URL is invalid.",
            "status_code": 403
        })

    try:
        if "next=" in unquote(next_url):
            parsed_next_url = urlparse.parse_qs(urlparse.urlparse(unquote(next_url)).query)
            next_url = dictor(parsed_next_url, "next.0")
    except Exception:
        next_url = request.GET.get("next") or get_default_next_url()

    # Only permit signin requests where the next_url is a safe URL
    allowed_hosts = set(dictor(saml2_auth_settings, "ALLOWED_REDIRECT_HOSTS", []))
    url_ok = is_safe_url(next_url, allowed_hosts)

    if not url_ok:
        return HttpResponseRedirect(
            get_reverse([denied, "denied", "django_saml2_auth:denied"]))  # type: ignore

    request.session["login_next_url"] = next_url

    saml_client = get_saml_client(get_assertion_url(request), acs, request)
    _, info = saml_client.prepare_for_authenticate(relay_state=next_url)  # type: ignore

    redirect_url = dict(info["headers"]).get("Location", "")
    return HttpResponseRedirect(redirect_url)


@exception_handler
def signout(request: HttpRequest) -> HttpResponse:
    """Custom sign-out view.

    Args:
        request (HttpRequest): Django request object.

    Returns:
        HttpResponse: Render the logout page.
    """
    logout(request)
    return render(request, "django_saml2_auth/signout.html")
