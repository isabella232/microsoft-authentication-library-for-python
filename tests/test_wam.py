from tests import unittest
import logging

from msal.wam import *


logging.basicConfig(level=logging.DEBUG)

class TestWam(unittest.TestCase):
    client_id = "26a7ee05-5602-4d76-a7ba-eae8b7b67941"  # A pre-configured test app

    def test_acquire_token_interactive(self):
        result = acquire_token_interactive(
            "https://login.microsoftonline.com/common",
            self.client_id,
            ["https://graph.microsoft.com/.default"],
            )
        self.assertIsNotNone(result.get("access_token"), result)

    def test_acquire_token_silent(self):
        result = acquire_token_silent(
            "https://login.microsoftonline.com/common",
            self.client_id,
            ["https://graph.microsoft.com/.default"],
            #{"some_sort_of_id": "placeholder"},  # TODO
            )
        self.assertIsNotNone(result.get("access_token"))

