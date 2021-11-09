from tests import unittest
import logging

from msal.wam import *


logging.basicConfig(level=logging.DEBUG)

class TestWam(unittest.TestCase):
    client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"  # A well-known app

    @unittest.skip("Not yet implemented")
    def test_acquire_token_interactive(self):
        acquire_token_interactive(
            "https://login.microsoftonline.com/common",
            #"my_client_id",
            "26a7ee05-5602-4d76-a7ba-eae8b7b67941",
            #["foo", "bar"],
            ["https://graph.microsoft.com/.default"],
            )

    def test_acquire_token_silent(self):
        result = acquire_token_silent(
            "https://login.microsoftonline.com/common",
            #"my_client_id",
            #self.client_id,
            "26a7ee05-5602-4d76-a7ba-eae8b7b67941",
            ["https://graph.microsoft.com/.default"],
            #{"some_sort_of_id": "placeholder"},  # TODO
            )
        self.assertIsNotNone(result.get("access_token"))

