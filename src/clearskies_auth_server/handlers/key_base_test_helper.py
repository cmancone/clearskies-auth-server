import json
import unittest
from unittest.mock import MagicMock, call
from types import SimpleNamespace
from jwcrypto import jwk
from .key_base import KeyBase
from clearskies.contexts import test


class KeyBaseTestHelper(unittest.TestCase):
    def setUp(self):
        self.key_id = "my_test_key_1"
        self.key = jwk.JWK.generate(
            kty="RSA",
            size=2048,
            kid=self.key_id,
            alg="RSA256",
            use="sig",
        )

        self.private_keys = {self.key_id: {**json.loads(self.key.export_private()), "issue_date": "1"}}
        self.public_keys = {self.key_id: {**json.loads(self.key.export_public()), "issue_date": "1"}}

        self.fetch_keys = MagicMock()
        self.fetch_keys.side_effect = [json.dumps(self.private_keys), json.dumps(self.public_keys)]
        self.secrets = SimpleNamespace(
            get=self.fetch_keys,
            upsert=MagicMock(),
        )
