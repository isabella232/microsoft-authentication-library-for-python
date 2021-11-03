from tests import unittest
import logging

from msal.wam import *


logging.basicConfig(level=logging.DEBUG)

class TestWam(unittest.TestCase):

    def test_acquire_token_interactive(self):
        acquire_token_interactive(
            "https://login.microsoftonline.com/common",
            "my_client_id",
            ["foo", "bar"],
            )

    @unittest.skip("Not yet implemented")
    def test_acquire_token_silent(self):
        acquire_token_silent(
            "https://login.microsoftonline.com/common",
            "my_client_id",
            ["foo", "bar"],
            {"some_sort_of_id": "placeholder"},
            )
