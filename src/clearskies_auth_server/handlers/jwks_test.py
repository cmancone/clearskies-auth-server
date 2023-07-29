import json
import unittest
from unittest.mock import MagicMock, call
from types import SimpleNamespace
from jwcrypto import jwk
from .key_base_test import KeyBaseTest
from .jwks import Jwks
from clearskies.contexts import test


class JwksTest(KeyBaseTest):
    def test_jwks(self):
        jwks = test(
            {
                "handler_class": Jwks,
                "handler_config": {
                    "path_to_private_keys": "/path/to/private",
                    "path_to_public_keys": "/path/to/public",
                },
            },
            bindings={"secrets": self.secrets},
        )
        result = jwks()
        self.assertEquals(200, result[1])
        self.assertEquals(
            [
                {
                    "kid": "my_test_key_1",
                    "alg": "RSA256",
                    "e": self.public_keys[self.key_id]["e"],
                    "kty": "RSA",
                    "n": self.public_keys[self.key_id]["n"],
                    "use": "sig",
                }
            ],
            result[0]["keys"],
        )
