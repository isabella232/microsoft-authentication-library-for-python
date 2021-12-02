"""This module acquires token via WAM, with the help of Mid-tier.

Mid-tier supports these Windows versions
https://github.com/AzureAD/microsoft-authentication-library-for-cpp/pull/2406/files
"""
from threading import Event
import json
import logging

import pymsalruntime  # See https://github.com/AzureAD/microsoft-authentication-library-for-cpp/pull/2419/files#diff-d5ea5122ff04e14411a4f695895c923daba73c117d6c8ceb19c4fa3520c3c08a
import win32gui  # Came from package pywin32

logger = logging.getLogger(__name__)


class _CallbackData:
    def __init__(self):
        self.signal = Event()
        self.auth_result = None

    def complete(self, auth_result):
        self.signal.set()
        self.auth_result = auth_result


def _read_account_by_id(account_id):
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
        return {
            "error": "broker_error",
            "error_description": "{}. Status: {}, Error code: {}, Tag: {}".format(
                error.get_context(),  # Available since pymsalruntime 0.0.4
                error.get_status(), error.get_error_code(), error.get_tag()),
            }
    id_token_claims = json.loads(result.get_id_token()) if result.get_id_token() else {}
    account = result.get_account()
    assert account.get_account_id() == id_token_claims.get("oid"), "Emperical observation"  # TBD
    return {k: v for k, v in {
        "access_token": result.get_access_token(),
        "expires_in": result.get_access_token_expiry_time(),
        #"scope": result.get_granted_scopes(),  # TODO
        "id_token_claims": id_token_claims,
        "client_info": account.get_client_info(),
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
    return callback_data.auth_result

def _signin_interactively(
        authority, client_id, scope,
        login_hint=None,
        window=None,
        ):
    params = pymsalruntime.MSALRuntimeAuthParameters(client_id, authority)
    params.set_requested_scopes(scope or "https://graph.microsoft.com/.default")
    params.set_redirect_uri(
        "https://login.microsoftonline.com/common/oauth2/nativeclient")
    callback_data = _CallbackData()
    pymsalruntime.signin_interactively(
        window or win32gui.GetDesktopWindow(),  # TODO: Remove win32gui
        params,
        "correlation", # TODO
        login_hint or "",  # Account hint
        lambda result, callback_data=callback_data: callback_data.complete(result))
    callback_data.signal.wait()
    return _convert_result(callback_data.auth_result)


def _acquire_token_silently(authority, client_id, account, scope):
    params = pymsalruntime.MSALRuntimeAuthParameters(client_id, authority)
    params.set_requested_scopes(scope)
    callback_data = _CallbackData()
    pymsalruntime.signin_silently(
        params,
        "correlation", # TODO
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


def acquire_token_interactive(
        authority,  # type: str
        client_id,  # type: str
        scopes,  # type: list[str]
        login_hint=None,
        **kwargs):
    """MSAL Python's acquire_token_interactive() will call this"""
    return _signin_interactively(
        authority,
        client_id,
        " ".join(scopes),
        login_hint=login_hint)


def acquire_token_silent(
        authority,  # type: str
        client_id,  # type: str
        scopes,  # type: list[str]
        account=None,  # TBD
        ):
    scope = " ".join(scopes)
    if account:
        wam_account = _read_account_by_id(account["some_sort_of_id"])  # TODO
    else:
        wam_account = _signin_silently(authority, client_id, scope).get_account()
    if wam_account:
        return _acquire_token_silently(authority, client_id, wam_account, scope)

