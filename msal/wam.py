"""This module acquires token via WAM, with the help of Mid-tier.

Mid-tier supports these Windows versions
https://github.com/AzureAD/microsoft-authentication-library-for-cpp/pull/2406/files
"""
from threading import Event
import json
import logging

import pymsalruntime  # See https://github.com/AzureAD/microsoft-authentication-library-for-cpp/pull/2419/files#diff-d5ea5122ff04e14411a4f695895c923daba73c117d6c8ceb19c4fa3520c3c08a


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
        lambda result, callback_data=callback_data: callback_data.complete(result)
        )
    callback_data.signal.wait()
    return callback_data.auth_result

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

def _signin_interactively():
    callback_data = _CallbackData()
    pymsalruntime.signin_interactively(
        # TODO: Add other input parameters
        lambda result, callback_data=callback_data: callback_data.complete(result))
    callback_data.signal.wait()
    return callback_data.auth_result

def _acquire_token_silently(authority, client_id, account, scope):
    params = pymsalruntime.MSALRuntimeAuthParameters(client_id, authority)
    params.set_requested_scopes(scope)
    callback_data = _CallbackData()
    pymsalruntime.signin_silently(
        params,
        "correlation", # TODO
        lambda result, callback_data=callback_data: callback_data.complete(result))
    callback_data.signal.wait()
    result = callback_data.auth_result
    return {k: v for k, v in {
        "error": result.get_error(),
        "access_token": result.get_access_token(),
        #"expires_in": result.get_access_token_expiry_time(),  # TODO
        #"scope": result.get_granted_scopes(),  # TODO
        "id_token_claims": json.loads(result.get_id_token())
            if result.get_id_token() else None,
        "account": result.get_account(),
        }.items() if v}

def _acquire_token_interactive(
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
    pymsalruntime.signin_interactively(
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
        **kwargs):
    """MSAL Python's acquire_token_interactive() will call this"""
    scope = " ".join(scopes)
    result = _signin_silently(authority, client_id)
    logger.debug("%s, %s, %s, %s, %s", client_id, scope, result, dir(result), result.get_error())
    if not result.get_account():
        result = _signin_interactively(authority, client_id)
    if not result.get_account():
        return {"error": result.get_error()}  # TODO

    result = _acquire_token_silently(
        authority, client_id, account, scope, **kwargs)
    if not result.get_access_token():
        result = _acquire_token_interactive(
            authority, client_id, account, scope, **kwargs)
    if not result.get_access_token():
        return {"error": result.get_error()}  # TODO
    # TODO: Also store the tokens and account into MSAL's token cache
    return {k: v for k, v in {
        "access_token": result.get_access_token(),
        "token_type": "Bearer",  # TODO: TBD
        "expires_in": result.get_access_token_expiry_time(),
        "id_token": result.get_id_token(),
        "scope": result.get_granted_scopes(),
        } if v is not None}


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

