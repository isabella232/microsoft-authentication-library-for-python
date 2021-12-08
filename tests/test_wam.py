from tests import unittest
import logging

from msal.wam import _signin_interactively, _acquire_token_silently


logging.basicConfig(level=logging.DEBUG)

class TestWam(unittest.TestCase):
    def test_interactive_then_silent(self):
        client_id = "26a7ee05-5602-4d76-a7ba-eae8b7b67941"  # A pre-configured test app
        authority = "https://login.microsoftonline.com/common"
        scope = "https://graph.microsoft.com/.default"

        result = _signin_interactively(authority, client_id, scope)
        self.assertIsNotNone(result.get("access_token"), result)

        account_id = result["_account_id"]
        result = _acquire_token_silently(authority, client_id, account_id, scope)
        self.assertIsNotNone(result.get("access_token"))

