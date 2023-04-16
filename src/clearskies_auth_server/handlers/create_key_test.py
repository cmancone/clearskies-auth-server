import json
import unittest
from unittest.mock import MagicMock, call
from types import SimpleNamespace
from jwcrypto import jwk
from .create_key import CreateKey
from clearskies.contexts import test
class CreateKeyTest(unittest.TestCase):
    def setUp(self):
        self.key_id = 'my_test_key_1'
        self.key = jwk.JWK.generate(
            kty='RSA',
            size=2048,
            kid=self.key_id,
            alg='RSA256',
            use='sig',
        )

        self.private_keys = {self.key_id: {**json.loads(self.key.export_private()), 'issued_at': ''}}
        self.public_keys = {self.key_id: {**json.loads(self.key.export_public()), 'issued_at': ''}}

        self.fetch_keys = MagicMock()
        self.fetch_keys.side_effect = [json.dumps(self.private_keys), json.dumps(self.public_keys)]
        self.secrets = SimpleNamespace(
            get=self.fetch_keys,
            upsert=MagicMock(),
        )

    def test_create_key(self):
        create_key = test(
            {
                'handler_class': CreateKey,
                'handler_config': {
                    'path_to_private_keys': '/path/to/private',
                    'path_to_public_keys': '/path/to/public',
                },
            },
            bindings={'secrets': self.secrets},
        )
        utcnow = str(create_key.build('utcnow'))
        result = create_key()
        self.assertEquals(200, result[1])
        key_id = result[0]['data']['id']

        self.secrets.get.assert_has_calls([
            call('/path/to/private', silent_if_not_found=True),
            call('/path/to/public', silent_if_not_found=True),
        ])

        upsert_calls = self.secrets.upsert.call_args_list

        self.assertEquals(
            '/path/to/private',
            upsert_calls[0].args[0],
        )
        # we're just going to check the keys (:shh:)
        saved_keys = list(json.loads(upsert_calls[0].args[1]).keys())
        self.assertEquals([self.key_id, key_id], saved_keys)

        self.assertEquals(
            '/path/to/public',
            upsert_calls[1].args[0],
        )

        saved_keys = list(json.loads(upsert_calls[1].args[1]).keys())
        self.assertEquals([self.key_id, key_id], saved_keys)
