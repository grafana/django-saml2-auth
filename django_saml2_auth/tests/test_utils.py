import pytest
from django.http import HttpRequest, HttpResponse
from django.urls import NoReverseMatch
from django_saml2_auth.exceptions import SAMLAuthError
from django_saml2_auth.utils import exception_handler, get_reverse, run_hook


def divide(a: int, b: int = 1) -> int:
    return int(a/b)


def hello(_: HttpRequest) -> HttpResponse:
    return HttpResponse(content="Hello, world!")


def goodbye(_: HttpRequest) -> HttpResponse:
    raise SAMLAuthError("Goodbye, world!", extra={
        "exc": RuntimeError("World not found!"),
        "exc_type": RuntimeError,
        "error_code": 0,
        "reason": "Internal world error!",
        "status_code": 500
    })


def test_run_hook_success():
    result = run_hook("django_saml2_auth.tests.test_utils.divide", 2, b=2)
    assert result == 1


def test_run_hook_no_function_path():
    with pytest.raises(SAMLAuthError) as exc_info:
        run_hook("")
        run_hook(None)

    assert str(exc_info.value) == "function_path isn't specified"


def test_run_hook_nothing_to_import():
    with pytest.raises(SAMLAuthError) as exc_info:
        run_hook("divide")

    assert str(exc_info.value) == "There's nothing to import. Check your hook's import path!"


def test_run_hook_import_error():
    with pytest.raises(SAMLAuthError) as exc_info:
        run_hook("django_saml2_auth.tests.test_utils.nonexistent_divide", 2, b=2)

    assert str(exc_info.value) == (
        "module 'django_saml2_auth.tests.test_utils' has no attribute 'nonexistent_divide'")
    assert isinstance(exc_info.value.extra["exc"], AttributeError)
    assert exc_info.value.extra["exc_type"] == AttributeError


def test_run_hook_division_by_zero():
    with pytest.raises(SAMLAuthError) as exc_info:
        run_hook("django_saml2_auth.tests.test_utils.divide", 2, b=0)

    assert str(exc_info.value) == "division by zero"
    # Actually a ZeroDivisionError wrapped in SAMLAuthError
    assert isinstance(exc_info.value.extra["exc"], ZeroDivisionError)
    assert exc_info.value.extra["exc_type"] == ZeroDivisionError


def test_get_reverse_success():
    result = get_reverse("acs")
    assert result == "/acs/"


def test_get_reverse_no_reverse_match():
    with pytest.raises(SAMLAuthError) as exc_info:
        get_reverse("nonexistent_view")

    assert str(exc_info.value) == "We got a URL reverse issue: ['nonexistent_view']"
    assert issubclass(exc_info.value.extra["exc_type"], NoReverseMatch)


def test_exception_handler_success():
    decorated_hello = exception_handler(hello)
    result = decorated_hello(HttpRequest())
    assert result.content.decode("utf-8") == "Hello, world!"


def test_exception_handler_handle_exception():
    decorated_goodbye = exception_handler(goodbye)
    result = decorated_goodbye(HttpRequest())
    contents = result.content.decode("utf-8")
    assert result.status_code == 500
    assert "Reason: Internal world error!" in contents
