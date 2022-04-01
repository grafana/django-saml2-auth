#!/usr/bin/env python
# -*- coding:utf-8 -*-

"""Endpoints for SAML SSO login"""

import urllib.parse as urlparse
from urllib.parse import unquote

from dictor import dictor
from django import get_version
from django.conf import settings
from django.contrib.auth import login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponseRedirect
from django.shortcuts import render
from django.template import TemplateDoesNotExist
try:
    from django.utils.http import url_has_allowed_host_and_scheme as is_safe_url
except ImportError:
    from django.utils.http import is_safe_url
from django.views.decorators.csrf import csrf_exempt
from django_saml2_auth.errors import INACTIVE_USER, INVALID_REQUEST_METHOD, USER_MISMATCH
from django_saml2_auth.exceptions import SAMLAuthError
from django_saml2_auth.saml import (decode_saml_response,
                                    extract_user_identity, get_assertion_url,
                                    get_default_next_url, get_saml_client)
from django_saml2_auth.user import (
    create_custom_or_default_jwt, decode_custom_or_default_jwt, get_or_create_user, get_user_id)
from django_saml2_auth.utils import exception_handler, get_reverse, is_jwt_well_formed, run_hook
from pkg_resources import parse_version


@login_required
def welcome(request: HttpRequest):
    try:
        return render(request, "django_saml2_auth/welcome.html", {"user": request.user})
    except TemplateDoesNotExist:
        return HttpResponseRedirect(get_default_next_url())


def denied(request: HttpRequest):
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
    user = extract_user_identity(authn_response.get_identity())

    next_url = request.session.get("login_next_url") or get_default_next_url()

    # A RelayState is an HTTP parameter that can be included as part of the SAML request and SAML response;
    # usually is meant to be an opaque identifier that is passed back without any modification or inspection,
    # and it is used to specify additional information to the SP or the IdP.
    # If RelayState params is passed, it could be JWT token that identifies the user trying to login
    # via sp_initiated_login endpoint, or it could be a URL used for redirection.
    relay_state = request.POST.get("RelayState")
    relay_state_is_token = is_jwt_well_formed(relay_state)
    if relay_state_is_token:
        redirected_user_id = decode_custom_or_default_jwt(relay_state)

        # This prevents users from entering an email on the SP, but use a different email on IdP
        if get_user_id(user) != redirected_user_id:
            raise SAMLAuthError("The user identifier doesn't match.", extra={
                "exc_type": ValueError,
                "error_code": USER_MISMATCH,
                "reason": "User identifier mismatch.",
                "status_code": 403
            })

    is_new_user, target_user = get_or_create_user(user)

    before_login_trigger = dictor(saml2_auth_settings, "TRIGGER.BEFORE_LOGIN")
    if before_login_trigger:
        run_hook(before_login_trigger, user)

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
        model_backend = "django.contrib.auth.backends.ModelBackend"
        login(request, target_user, model_backend)

        after_login_trigger = dictor(saml2_auth_settings, "TRIGGER.AFTER_LOGIN")
        if after_login_trigger:
            run_hook(after_login_trigger, request.session, user)
    else:
        raise SAMLAuthError("The target user is inactive.", extra={
            "exc_type": Exception,
            "error_code": INACTIVE_USER,
            "reason": "User is inactive.",
            "status_code": 500
        })

    if is_new_user:
        try:
            return render(request, "django_saml2_auth/welcome.html", {"user": request.user})
        except TemplateDoesNotExist:
            return HttpResponseRedirect(next_url)
    else:
        return HttpResponseRedirect(next_url)


@exception_handler
def sp_initiated_login(request: HttpRequest) -> HttpResponseRedirect:
    # User must be created first by the IdP-initiated SSO (acs)
    if request.method == "GET":
        if request.GET.get("token"):
            user_id = decode_custom_or_default_jwt(request.GET.get("token"))
            saml_client = get_saml_client(get_assertion_url(request), acs, user_id)
            jwt_token = create_custom_or_default_jwt(user_id)
            _, info = saml_client.prepare_for_authenticate(sign=False, relay_state=jwt_token)
            redirect_url = dict(info["headers"]).get("Location", "")
            if not redirect_url:
                return HttpResponseRedirect(get_reverse([denied, "denied", "django_saml2_auth:denied"]))
            return HttpResponseRedirect(redirect_url)
    else:
        raise SAMLAuthError("Request method is not supported.", extra={
            "exc_type": Exception,
            "error_code": INVALID_REQUEST_METHOD,
            "reason": "Request method is not supported.",
            "status_code": 404
        })


@exception_handler
def signin(request: HttpRequest):
    saml2_auth_settings = settings.SAML2_AUTH

    next_url = request.GET.get("next") or get_default_next_url()

    try:
        if "next=" in unquote(next_url):
            parsed_next_url = urlparse.parse_qs(urlparse.urlparse(unquote(next_url)).query)
            next_url = dictor(parsed_next_url, "next.0")
    except:
        next_url = request.GET.get("next") or get_default_next_url()

    # Only permit signin requests where the next_url is a safe URL
    allowed_hosts = set(dictor(saml2_auth_settings, "ALLOWED_REDIRECT_HOSTS", []))
    if parse_version(get_version()) >= parse_version("2.0"):
        url_ok = is_safe_url(next_url, allowed_hosts)
    else:
        url_ok = is_safe_url(next_url)

    if not url_ok:
        return HttpResponseRedirect(get_reverse([denied, "denied", "django_saml2_auth:denied"]))

    request.session["login_next_url"] = next_url

    saml_client = get_saml_client(get_assertion_url(request), acs)
    _, info = saml_client.prepare_for_authenticate(relay_state=next_url)

    redirect_url = dict(info["headers"]).get("Location", "")
    return HttpResponseRedirect(redirect_url)


@exception_handler
def signout(request: HttpRequest):
    logout(request)
    return render(request, "django_saml2_auth/signout.html")
