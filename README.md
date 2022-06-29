# Django SAML2 Authentication

[![PyPI](https://img.shields.io/pypi/v/grafana-django-saml2-auth?label=version&logo=pypi)](https://pypi.org/project/grafana-django-saml2-auth/) [![GitHub Workflow Status](https://img.shields.io/github/workflow/status/grafana/django-saml2-auth/deploy?logo=github)](https://github.com/grafana/django-saml2-auth/actions) [![Coveralls](https://img.shields.io/coveralls/github/grafana/django-saml2-auth?logo=coveralls)](https://coveralls.io/github/grafana/django-saml2-auth) [![Downloads](https://pepy.tech/badge/grafana-django-saml2-auth)](https://pepy.tech/project/grafana-django-saml2-auth)

This plugin provides a simple way to integrate SAML2 Authentication into your Django-powered app. SAML SSO is a standard, so practically any SAML2 based SSO identity provider is supported.

This plugin supports both identity provider and service provider-initiated SSO:

- For IdP-initiated SSO, the user should sign in to their identity provider platform, e.g., Okta, and click on the application that authorizes and redirects the user to the service provider, that is your platform.
- For SP-initiated SSO, the user should first exist on your platform, either by signing in via the first method (IdP-initiated SSO) or any other custom solution. It can be configured to be redirected to the correct application on the identity provider platform.

For IdP-initiated SSO, the user will be created if it doesn't exist. Still, for SP-initiated SSO, the user should exist in your platform for the code to detect and redirect them to the correct application on the identity provider platform.

- [Django SAML2 Authentication](#django-saml2-authentication)
  - [Project Information](#project-information)
  - [Donate](#donate)
  - [Installation](#installation)
  - [How to use?](#how-to-use)
  - [Module Settings](#module-settings)
  - [JWT Signing Algorithm and Settings](#jwt-signing-algorithm-and-settings)
    - [Custom token triggers](#custom-token-triggers)
  - [Customize Error Messages](#customize-error-messages)
  - [For Okta Users](#for-okta-users)

## Project Information

- Original Author: Fang Li ([@fangli](https://github.com/fangli))
- Maintainer: Mostafa Moradian ([@mostafa](https://github.com/mostafa))
- Version support matrix:
    | **Python**                  | **Django** | **django-saml2-auth** |
    | --------------------------- | ---------- | --------------------- |
    | 3.7.x, 3.8.x, 3.9.x, 3.10.x | 2.2.x      | >=3.4.0               |
    | 3.7.x, 3.8.x, 3.9.x, 3.10.x | 3.2.x      | >=3.4.0               |
    | 3.8.x, 3.9.x, 3.10.x        | 4.0.x      | >=3.4.0               |

- Release log is available [here](RELEASE-LOG.md).

- For contribution, read [contributing guide](CONTRIBUTING.md).

## CycloneDX SBOM

From [v3.6.1](https://github.com/grafana/django-saml2-auth/releases/tag/v3.6.1), CycloneDX SBOMs will be generated for [requirements.txt](./requirements.txt) and [requirements_test.txt](./requirements_test.txt) and it can be accessed from the latest build of GitHub Actions for a tagged release, for example, [this one](https://github.com/grafana/django-saml2-auth/actions/runs/2245422253). The artifacts are only kept for 90 days.

## Donate

Please give us a shiny ![star](https://img.shields.io/github/stars/grafana/django-saml2-auth.svg?style=social&label=Star&maxAge=86400) and help spread the word.

## Installation

You can install this plugin via `pip`. Make sure you update `pip` to be able to install from git:

```bash
pip install grafana-django-saml2-auth
```

or from source:

```bash
git clone https://github.com/grafana/django-saml2-auth
cd django-saml2-auth
python setup.py install
```

`xmlsec` is also required by `pysaml2`, so it must be installed:

``` bash
// RPM-based distributions
# yum install xmlsec1
// DEB-based distributions
# apt-get install xmlsec1
// macOS
# brew install xmlsec1
```

[Windows binaries](https://www.zlatkovic.com/projects/libxml/index.html) are also available.

## How to use?

1. Once you have the library installed or in your `requirements.txt`, import the views module in your root `urls.py`:

    ```python
    import django_saml2_auth.views
    ```

2. Override the default login page in the root `urls.py` file, by adding these lines **BEFORE** any `urlpatterns`:

    ```python
    # These are the SAML2 related URLs. You can change "^saml2_auth/" regex to
    # any path you want, like "^sso/", "^sso_auth/", "^sso_login/", etc. (required)
    url(r'^sso/', include('django_saml2_auth.urls')),

    # The following line will replace the default user login with SAML2 (optional)
    # If you want to specific the after-login-redirect-URL, use parameter "?next=/the/path/you/want"
    # with this view.
    url(r'^accounts/login/$', django_saml2_auth.views.signin),

    # The following line will replace the admin login with SAML2 (optional)
    # If you want to specific the after-login-redirect-URL, use parameter "?next=/the/path/you/want"
    # with this view.
    url(r'^admin/login/$', django_saml2_auth.views.signin),
    ```

3. Add `'django_saml2_auth'` to `INSTALLED_APPS` in your django `settings.py`:

    ```python
    INSTALLED_APPS = [
        '...',
        'django_saml2_auth',
    ]
    ```

4. In `settings.py`, add the SAML2 related configuration:

    Please note, the only required setting is **METADATA\_AUTO\_CONF\_URL** or the existence of a **GET\_METADATA\_AUTO\_CONF\_URLS** trigger function. The following block shows all required and optional configuration settings and their default values.

    ```python
    SAML2_AUTH = {
        # Metadata is required, choose either remote url or local file path
        'METADATA_AUTO_CONF_URL': '[The auto(dynamic) metadata configuration URL of SAML2]',
        'METADATA_LOCAL_FILE_PATH': '[The metadata configuration file path]',

        'DEBUG': False,  # Send debug information to a log file

        # Optional settings below
        'DEFAULT_NEXT_URL': '/admin',  # Custom target redirect URL after the user get logged in. Default to /admin if not set. This setting will be overwritten if you have parameter ?next= specificed in the login URL.
        'CREATE_USER': True,  # Create a new Django user when a new user logs in. Defaults to True.
        'NEW_USER_PROFILE': {
            'USER_GROUPS': [],  # The default group name when a new user logs in
            'ACTIVE_STATUS': True,  # The default active status for new users
            'STAFF_STATUS': False,  # The staff status for new users
            'SUPERUSER_STATUS': False,  # The superuser status for new users
        },
        'ATTRIBUTES_MAP': {  # Change Email/UserName/FirstName/LastName to corresponding SAML2 userprofile attributes.
            'email': 'user.email',
            'username': 'user.username',
            'first_name': 'user.first_name',
            'last_name': 'user.last_name',
            'token': 'Token',  # Mandatory, can be unrequired if TOKEN_REQUIRED is False
            'groups': 'Groups',  # Optional
        },
        'GROUPS_MAP': {  # Optionally allow mapping SAML2 Groups to Django Groups
            'SAML Group Name': 'Django Group Name',
        },
        'TRIGGER': {
            'CREATE_USER': 'path.to.your.new.user.hook.method',
            'BEFORE_LOGIN': 'path.to.your.login.hook.method',
            'AFTER_LOGIN': 'path.to.your.after.login.hook.method',
            # Optional. This is executed right before METADATA_AUTO_CONF_URL.
            # For systems with many metadata files registered allows to narrow the search scope.
            'GET_USER_ID_FROM_SAML_RESPONSE': 'path.to.your.get.user.from.saml.hook.method',
            # This can override the METADATA_AUTO_CONF_URL to enumerate all existing metadata autoconf URLs
            'GET_METADATA_AUTO_CONF_URLS': 'path.to.your.get.metadata.conf.hook.method',
        },
        'ASSERTION_URL': 'https://mysite.com',  # Custom URL to validate incoming SAML requests against
        'ENTITY_ID': 'https://mysite.com/saml2_auth/acs/',  # Populates the Issuer element in authn request
        'NAME_ID_FORMAT': FormatString,  # Sets the Format property of authn NameIDPolicy element, e.g. 'user.email'
        'USE_JWT': True,  # Set this to True if you are running a Single Page Application (SPA) with Django Rest Framework (DRF), and are using JWT authentication to authorize client users
        'JWT_ALGORITHM': 'HS256',  # JWT algorithm to sign the message with
        'JWT_SECRET': 'your.jwt.secret',  # JWT secret to sign the message with
        'JWT_PRIVATE_KEY': '--- YOUR PRIVATE KEY ---',  # Private key to sign the message with. The algorithm should be set to RSA256 or a more secure alternative.
        'JWT_PRIVATE_KEY_PASSPHRASE': 'your.passphrase',  # If your private key is encrypted, you might need to provide a passphrase for decryption
        'JWT_PUBLIC_KEY': '--- YOUR PUBLIC KEY ---',  # Public key to decode the signed JWT token
        'JWT_EXP': 60,  # JWT expiry time in seconds
        'FRONTEND_URL': 'https://myfrontendclient.com',  # Redirect URL for the client if you are using JWT auth with DRF. See explanation below
        'LOGIN_CASE_SENSITIVE': True,  # whether of not to get the user in case_sentive mode
        'AUTHN_REQUESTS_SIGNED': True, # Require each authentication request to be signed
        'LOGOUT_REQUESTS_SIGNED': True,  # Require each logout request to be signed
        'WANT_ASSERTIONS_SIGNED': True,  # Require each assertion to be signed
        'WANT_RESPONSE_SIGNED': True,  # Require response to be signed
        'ACCEPTED_TIME_DIFF': None,  # Accepted time difference between your server and the Identity Provider
        'ALLOWED_REDIRECT_HOSTS': ["https://myfrontendclient.com"], # Allowed hosts to redirect to using the ?next parameter
        'TOKEN_REQUIRED': True,  # Whether or not to require the token parameter in the SAML assertion
    }
    ```

5. In your SAML2 SSO identity provider, set the Single-sign-on URL and Audience URI (SP Entity ID) to <http://your-domain/saml2_auth/acs/>

## Module Settings

| **Field name**                              | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                                             | **Data type(s)** | **Default value(s)**                                                                                                                     | **Example**                                              |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| **METADATA\_AUTO\_CONF\_URL**               | Auto SAML2 metadata configuration URL                                                                                                                                                                                                                                                                                                                                                                                                                       | `str`            | `None`                                                                                                                                   | `https://ORG.okta.com/app/APP-ID/sso/saml/metadata`      |
| **METADATA\_LOCAL\_FILE\_PATH**             | SAML2 metadata configuration file path                                                                                                                                                                                                                                                                                                                                                                                                                      | `str`            | `None`                                                                                                                                   | `/path/to/the/metadata.xml`                              |
| **DEBUG**                                   | Send debug information to a log file                                                                                                                                                                                                                                                                                                                                                                                                                        | `bool`           | `False`                                                                                                                                  |                                                          |
| **DEFAULT\_NEXT\_URL**                      | Custom target redirect URL after the user get logged in. Default to /admin if not set. This setting will be overwritten if you have parameter `?next=` specificed in the login URL.                                                                                                                                                                                                                                                                         | `str`            | `admin:index`                                                                                                                            | `https://app.example.com/account/login`                  |
| **CREATE\_USER**                            | Determines if a new Django user should be created for new users                                                                                                                                                                                                                                                                                                                                                                                             | `bool`           | `True`                                                                                                                                   |                                                          |
| **NEW\_USER\_PROFILE**                      | Default settings for newly created users                                                                                                                                                                                                                                                                                                                                                                                                                    | `dict`           | `{'USER_GROUPS': [], 'ACTIVE_STATUS': True, 'STAFF_STATUS': False, 'SUPERUSER_STATUS': False}`                                           |                                                          |
| **ATTRIBUTES\_MAP**                         | Mapping of Django user attributes to SAML2 user attributes                                                                                                                                                                                                                                                                                                                                                                                                  | `dict`           | `{'email': 'user.email', 'username': 'user.username', 'first_name': 'user.first_name', 'last_name': 'user.last_name', 'token': 'token'}` | `{'your.field': 'SAML.field'}`                           |
| **TOKEN\_REQUIRED**                         | Set this to `False` if you don't require the token parameter in the SAML assertion (in the attributes map)                                                                                                                                                                                                                                                                                                                                                  | `bool`           | `True`                                                                                                                                   |                                                          |
| **TRIGGER**                                 | Hooks to trigger additional actions during user login and creation flows. These `TRIGGER` hooks are strings containing a [dotted module name](https://docs.python.org/3/tutorial/modules.html#packages) which point to a method to be called. The referenced method should accept a single argument: a dictionary of attributes and values sent by the identity provider, representing the user's identity. Triggers will be executed only if they are set. | `dict`           | `{}`                                                                                                                                     |                                                          |
| **TRIGGER.CREATE\_USER**                    | A method to be called upon new user creation. This method will be called before the new user is logged in and after the user's record is created. This method should accept ONE parameter of user dict.                                                                                                                                                                                                                                                     | `str`            | `None`                                                                                                                                   | `my_app.models.users.create`                             |
| **TRIGGER.BEFORE\_LOGIN**                   | A method to be called when an existing user logs in. This method will be called before the user is logged in and after the SAML2 identity provider returns user attributes. This method should accept ONE parameter of user dict.                                                                                                                                                                                                                           | `str`            | `None`                                                                                                                                   | `my_app.models.users.before_login`                       |
| **TRIGGER.AFTER\_LOGIN**                    | A method to be called when an existing user logs in. This method will be called after the user is logged in and after the SAML2 identity provider returns user attributes. This method should accept TWO parameters of session and user dict.                                                                                                                                                                                                               | `str`            | `None`                                                                                                                                   | `my_app.models.users.after_login`                        |
| **TRIGGER.GET\_METADATA\_AUTO\_CONF\_URLS** | A hook function that returns a list of metadata Autoconf URLs. This can override the `METADATA_AUTO_CONF_URL` to enumerate all existing metadata autoconf URLs.                                                                                                                                                                                                                                                                                             | `str`            | `None`                                                                                                                                   | `my_app.models.users.get_metadata_autoconf_urls`         |
| **TRIGGER.CUSTOM\_DECODE\_JWT**             | A hook function to decode the user JWT. This method will be called instead of the `decode_jwt_token` default function and should return the user_model.USERNAME_FIELD. This method accepts one parameter: `token`.                                                                                                                                                                                                                                          | `str`            | `None`                                                                                                                                   | `my_app.models.users.decode_custom_token`                |
| **TRIGGER.CUSTOM\_CREATE\_JWT**             | A hook function to create a custom JWT for the user. This method will be called instead of the `create_jwt_token` default function and should return the token. This method accepts one parameter: `user`.                                                                                                                                                                                                                                                  | `str`            | `None`                                                                                                                                   | `my_app.models.users.create_custom_token`                |
| **TRIGGER.CUSTOM\_TOKEN\_QUERY**            | A hook function to create a custom query params with the JWT for the user. This method will be called after `CUSTOM_CREATE_JWT` to populate a query and attach it to a URL; should return the query params containing the token (e.g., `?token=encoded.jwt.token`). This method accepts one parameter: `token`.                                                                                                                                             | `str`            | `None`                                                                                                                                   | `my_app.models.users.get_custom_token_query`             |
| **ASSERTION\_URL**                          | A URL to validate incoming SAML responses against. By default, `django-saml2-auth` will validate the SAML response's Service Provider address against the actual HTTP request's host and scheme. If this value is set, it will validate against `ASSERTION_URL` instead - perfect for when Django is running behind a reverse proxy.                                                                                                                        | `str`            | `https://example.com`                                                                                                                    |                                                          |
| **ENTITY\_ID**                              | The optional entity ID string to be passed in the 'Issuer' element of authentication request, if required by the IDP.                                                                                                                                                                                                                                                                                                                                       | `str`            | `None`                                                                                                                                   | `https://exmaple.com/sso/acs`                            |
| **NAME\_ID\_FORMAT**                        | Set to the string `'None'`, to exclude sending the `'Format'` property of the `'NameIDPolicy'` element in authentication requests.                                                                                                                                                                                                                                                                                                                          | `str`            | `<urn:oasis:names:tc:SAML:2.0:nameid-format:transient>`                                                                                  |                                                          |
| **USE\_JWT**                                | Set this to the boolean `True` if you are using Django with JWT authentication                                                                                                                                                                                                                                                                                                                                                                              | `bool`           | `False`                                                                                                                                  |                                                          |
| **JWT\_ALGORITHM**                          | JWT algorithm (str) to sign the message with: [supported algorithms](https://pyjwt.readthedocs.io/en/stable/algorithms.html).                                                                                                                                                                                                                                                                                                                               | `str`            | `HS512` or `RS512`                                                                                                                       |                                                          |
| **JWT\_SECRET**                             | JWT secret to sign the message if an HMAC is used with the SHA hash algorithm (`HS*`).                                                                                                                                                                                                                                                                                                                                                                      | `str`            | `None`                                                                                                                                   |                                                          |
| **JWT\_PRIVATE\_KEY**                       | Private key (str) to sign the message with. The algorithm should be set to `RSA256` or a more secure alternative.                                                                                                                                                                                                                                                                                                                                           | `str` or `bytes` | `--- YOUR PRIVATE KEY ---`                                                                                                               |                                                          |
| **JWT\_PRIVATE\_KEY\_PASSPHRASE**           | If your private key is encrypted, you must provide a passphrase for decryption.                                                                                                                                                                                                                                                                                                                                                                             | `str` or `bytes` | `None`                                                                                                                                   |                                                          |
| **JWT\_PUBLIC\_KEY**                        | Public key to decode the signed JWT token.                                                                                                                                                                                                                                                                                                                                                                                                                  | `str` or `bytes` | `'--- YOUR PUBLIC KEY ---'`                                                                                                              |                                                          |
| **JWT\_EXP**                                | JWT expiry time in seconds                                                                                                                                                                                                                                                                                                                                                                                                                                  | `int`            | 60                                                                                                                                       |                                                          |
| **FRONTEND\_URL**                           | If `USE_JWT` is `True`, you should set the URL to where your frontend is located (will default to `DEFAULT_NEXT_URL` if you fail to do so). Once the client is authenticated through the SAML SSO, your client is redirected to the `FRONTEND_URL` with the JWT token as `token` query parameter. Example: `https://app.example.com/?&token=<your.jwt.token`. With the token, your SPA can now authenticate with your API.                                  | `str`            | `admin:index`                                                                                                                            |                                                          |
| **AUTHN\_REQUESTS\_SIGNED**                | Set this to `False` if your provider doesn't sign each authorization request.                                                                                                                                                                                                                                                                                                                                                                                           | `bool`           | `True`                                                                                                                                   |
| **LOGOUT\_REQUESTS\_SIGNED**                | Set this to `False` if your provider doesn't sign each logout request.                                                                                                                                                                                                                                                                                                                                                                                           | `bool`           | `True`                                                                                                                                   | |
| **WANT\_ASSERTIONS\_SIGNED**                | Set this to `False` if your provider doesn't sign each assertion.                                                                                                                                                                                                                                                                                                                                                                                           | `bool`           | `True`                                                                                                                                   |                                                          |
| **WANT\_RESPONSE\_SIGNED**                  | Set this to `False` if you don't want your provider to sign the response.                                                                                                                                                                                                                                                                                                                                                                                   | `bool`           | `True`                                                                                                                                   |                                                          |
| **ACCEPTED\_TIME\_DIFF**                    | Sets the [accepted time diff](https://pysaml2.readthedocs.io/en/latest/howto/config.html#accepted-time-diff) in seconds                                                                                                                                                                                                                                                                                                                                     | `int` or `None`  | `None`                                                                                                                                   |                                                          |
| **ALLOWED\_REDIRECT\_HOSTS**                | Allowed hosts to redirect to using the `?next=` parameter                                                                                                                                                                                                                                                                                                                                                                                                   | `list`           | `[]`                                                                                                                                     | `['https://app.example.com', 'https://api.exmaple.com']` |

### Triggers
| **Setting name**                            | **Description**                                                                                                                             | **Interface**                                                                                 |
|---------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|
| **GET\_METADATA\_AUTO\_CONF\_URLS**         | Auto SAML2 metadata configuration URL                                                                                                       | get_metadata_auto_conf_urls(user_id: Optional[str] = None) -> Optional[List[Dict[str, str]]]  |
| **GET\_USER_ID\_FROM\_SAML\_RESPONSE**      | Allows retrieving a user ID before GET_METADATA_AUTO_CONF_URLS gets triggered. Warning: SAML response still not verified. Use with caution! | get_user_id_from_saml_response(saml_response: str, user_id: Optional[str]) -> Optional[str]   |



## JWT Signing Algorithm and Settings

Both symmetric and asymmetric signing functions are [supported](https://pyjwt.readthedocs.io/en/stable/algorithms.html). If you want to use symmetric signing using a secret key, use either of the following algorithms plus a secret key:

- HS256
- HS384
- HS512

```python
{
    ...
    'USE_JWT': True,
    'JWT_ALGORITHM': 'HS256',
    'JWT_SECRET': 'YOU.ULTRA.SECURE.SECRET',
    ...
}
```

Otherwise if you want to use your PKI key-pair to sign JWT tokens, use either of the following algorithms and then set the following fields:

- RS256
- RS384
- RS512
- ES256
- ES256K
- ES384
- ES521
- ES512
- PS256
- PS384
- PS512
- EdDSA

```python
{
    ...
    'USE_JWT': True,
    'JWT_ALGORITHM': 'RS256',
    'JWT_PRIVATE_KEY': '--- YOUR PRIVATE KEY ---',
    'JWT_PRIVATE_KEY_PASSPHRASE': 'your.passphrase',  # Optional, if your private key is encrypted
    'JWT_PUBLIC_KEY': '--- YOUR PUBLIC KEY ---',
    ...
}
```

*Note:* If both PKI fields and `JWT_SECRET` are defined, the `JWT_ALGORITHM` decides which method to use for signing tokens.

### Custom token triggers

This is an example of the functions that could be passed to the `TRIGGER.CUSTOM_CREATE_JWT` (it uses the [DRF Simple JWT library](https://github.com/jazzband/djangorestframework-simplejwt/blob/master/docs/index.rst)) and to `TRIGGER.CUSTOM_TOKEN_QUERY`:

``` python
from rest_framework_simplejwt.tokens import RefreshToken


def get_custom_jwt(user):
    """Create token for user and return it"""
    return RefreshToken.for_user(user)


def get_custom_token_query(refresh):
    """Create url query with refresh and access token"""
    return "?%s%s%s%s%s" % ("refresh=", str(refresh), "&", "access=", str(refresh.access_token))

```

## Customize Error Messages

The default permission `denied`, `error` and user `welcome` page can be overridden.

To override these pages put a template named 'django\_saml2\_auth/error.html', 'django\_saml2\_auth/welcome.html' or 'django\_saml2\_auth/denied.html' in your project's template folder.

If a 'django\_saml2\_auth/welcome.html' template exists, that page will be shown to the user upon login instead of the user being redirected to the previous visited page. This welcome page can contain some first-visit notes and welcome words. The [Django user object](https://docs.djangoproject.com/en/1.9/ref/contrib/auth/#django.contrib.auth.models.User) is available within the template as the `user` template variable.

To enable a logout page, add the following lines to `urls.py`, before any `urlpatterns`:

```python
# The following line will replace the default user logout with the signout page (optional)
url(r'^accounts/logout/$', django_saml2_auth.views.signout),

# The following line will replace the default admin user logout with the signout page (optional)
url(r'^admin/logout/$', django_saml2_auth.views.signout),
```

To override the built in signout page put a template named 'django\_saml2\_auth/signout.html' in your project's template folder.

If your SAML2 identity provider uses user attribute names other than the defaults listed in the `settings.py` `ATTRIBUTES_MAP`, update them in `settings.py`.

## For Okta Users

I created this plugin originally for Okta. The `METADATA_AUTO_CONF_URL` needed in `settings.py` can be found in the Okta Web UI by navigating to the SAML2 app's `Sign On` tab. In the `Settings` box, you should see:

    Identity Provider metadata is available if this application supports dynamic configuration.

The `Identity Provider metadata` link is the `METADATA_AUTO_CONF_URL`.

More information can be found in the [Okta Developer Documentation](https://developer.okta.com/docs/guides/saml-application-setup/overview/).
