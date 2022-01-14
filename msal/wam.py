"""This module acquires token via WAM, with the help of Mid-tier.

Mid-tier supports these Windows versions
https://github.com/AzureAD/microsoft-authentication-library-for-cpp/pull/2406/files
"""
from threading import Event
import json
import logging

import pymsalruntime  # ImportError would be raised on unsupported platforms such as Windows 8
    # Its API description is available in site-packages/pymsalruntime/PyMsalRuntime.pyi
import win32gui  # Came from package pywin32
import win32console  # Came from package pywin32

logger = logging.getLogger(__name__)


class NeedRedirectURI(ValueError):
    pass


class _CallbackData:
    def __init__(self):
        self.signal = Event()
        self.auth_result = None

    def complete(self, auth_result):
        self.signal.set()
        self.auth_result = auth_result


def _convert_error(error):
    return {
        "error": "broker_error",
        "error_description": "{}. Status: {}, Error code: {}, Tag: {}".format(
            error.get_context(),  # Available since pymsalruntime 0.0.4
            error.get_status(), error.get_error_code(), error.get_tag()),
        }


def _read_account_by_id(account_id):
    """Return the callback result which contains the account or error"""
    callback_data = _CallbackData()
    pymsalruntime.read_account_by_id(
        account_id,
        "correlation_id",
        lambda result, callback_data=callback_data: callback_data.complete(result)
        )
    callback_data.signal.wait()
    return callback_data.auth_result


def _convert_result(result):  # Mimic an on-the-wire response from AAD
    error = result.get_error()
    if error:
        return _convert_error(error)
    id_token_claims = json.loads(result.get_id_token()) if result.get_id_token() else {}
    account = result.get_account()
    assert account, "Account is expected to be always available"
    ## Note: As of pymsalruntime 0.1.0, only wam_account_ids property is available
    #account.get_account_property("wam_account_ids")
    return {k: v for k, v in {
        "access_token": result.get_access_token(),
        "expires_in": result.get_access_token_expiry_time(),
        #"scope": result.get_granted_scopes(),  # TODO
        "id_token_claims": id_token_claims,
        "client_info": account.get_client_info(),
        "_account_id": account.get_account_id(),
        }.items() if v}


def _signin_silently(authority, client_id, scope):
    params = pymsalruntime.MSALRuntimeAuthParameters(client_id, authority)
    params.set_requested_scopes(scope or "https://graph.microsoft.com/.default")
    callback_data = _CallbackData()
    pymsalruntime.signin_silently(
        params,
        "correlation", # TODO
        lambda result, callback_data=callback_data: callback_data.complete(result))
    callback_data.signal.wait()
    return _convert_result(callback_data.auth_result)


def _signin_interactively(
        authority, client_id, scope,
        window=None,
        prompt=None,
        login_hint=None,
        claims=None,
        **kwargs):
    params = pymsalruntime.MSALRuntimeAuthParameters(client_id, authority)
    params.set_requested_scopes(scope or "https://graph.microsoft.com/.default")
    params.set_redirect_uri("placeholder")  # pymsalruntime 0.1 requires non-empty str,
        # the actual redirect_uri will be a value hardcoded by the underlying WAM
    if prompt:
        if prompt == "select_account":
            params.set_select_account_option(
                pymsalruntime.SelectAccountOption.SHOWLOCALACCOUNTSCONTROL)
        else:
            # TODO: MSAL Python might need to error out on other prompt values
            logger.warn("prompt=%s is not supported on this platform", prompt)
    for k, v in kwargs.items():  # This can be used to support domain_hint, max_age, etc.
        if v is not None:
            params.set_additional_query_parameter(k, str(v))  # TODO: End-to-end test
    if claims:
        params.set_decoded_claims(claims)
    callback_data = _CallbackData()
    pymsalruntime.signin_interactively(
        window or win32console.GetConsoleWindow() or win32gui.GetDesktopWindow(),  # TODO: Remove win32gui
        params,
        "correlation", # TODO
        login_hint or "",  # TODO: account_hint is meant to accept login_hint, while set_login_hint() is not
        lambda result, callback_data=callback_data: callback_data.complete(result))
    callback_data.signal.wait()
    result =_convert_result(callback_data.auth_result)
    if "AADSTS50011" in result.get("error_description", ""):
        raise NeedRedirectURI(
            "Please register one more redirect_uri to your app: "
            "ms-appx-web://Microsoft.AAD.BrokerPlugin/{}".format(client_id))
    return result


def _acquire_token_silently(authority, client_id, account_id, scope, claims=None):
    account = _read_account_by_id(account_id)
    error = account.get_error()
    if error:
        return _convert_error(error)
    params = pymsalruntime.MSALRuntimeAuthParameters(client_id, authority)
    params.set_requested_scopes(scope)
    if claims:
        params.set_decoded_claims(claims)
    callback_data = _CallbackData()
    pymsalruntime.acquire_token_silently(
        params,
        "correlation", # TODO
        account.get_account(),
        lambda result, callback_data=callback_data: callback_data.complete(result))
    callback_data.signal.wait()
    return _convert_result(callback_data.auth_result)


def _acquire_token_interactively(
        authority,
        client_id,
        account,
        scopes,
        prompt=None,  # TODO: Perhaps WAM would not accept this?
        login_hint=None,  # type: Optional[str]
        domain_hint=None,  # TODO: Perhaps WAM would not accept this?
        claims_challenge=None,
        timeout=None,  # TODO
        extra_scopes_to_consent=None,  # TODO: Perhaps WAM would not accept this?
        max_age=None,  # TODO: Perhaps WAM would not accept this?
        **kwargs):
    params = pymsalruntime.MSALRuntimeAuthParameters(client_id, authority)
    params.set_requested_scopes(" ".join(scopes))
    if login_hint:
        params.set_login_hint(login_hint)
    if claims_challenge:
        params.set_claims(claims_challenge)
    # TODO: Wire up other input parameters too
    callback_data = _CallbackData()
    pymsalruntime.acquire_token_interactively(
        window,  # TODO
        params,
        "correlation", # TODO
        account,
        lambda result, callback_data=callback_data: callback_data.complete(result))
    callback_data.signal.wait()
    return callback_data.auth_result

