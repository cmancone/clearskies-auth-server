import json
import unittest
from unittest.mock import MagicMock, call
from types import SimpleNamespace
from jwcrypto import jwk
from .key_base_test_helper import KeyBaseTestHelper
from .list_keys import ListKeys
from clearskies.contexts import test


class ListKeysTest(KeyBaseTestHelper):
    def test_list_keys(self):
        list_keys = test(
            {
                "handler_class": ListKeys,
                "handler_config": {
                    "path_to_private_keys": "/path/to/private",
                    "path_to_public_keys": "/path/to/public",
                },
            },
            bindings={"secrets": self.secrets},
        )
        result = list_keys()
        self.assertEquals(200, result[1])
        self.assertEquals(
            [{"id": "my_test_key_1", "algorithm": "RSA256", "issue_date": "1"}],
            result[0]["data"],
        )
