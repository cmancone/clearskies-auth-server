import json
import unittest
from unittest.mock import MagicMock, call
from types import SimpleNamespace
from jwcrypto import jwk
from .key_base_test import KeyBaseTest
from .create_key import CreateKey
from clearskies.contexts import test
import datetime
class CreateKeyTest(KeyBaseTest):
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

    def test_fetch_and_check_keys_success(self):
        test = CreateKey('di', self.secrets, datetime, 'uuid')
        keys = test.fetch_and_check_keys('/path/to/private')

        self.assertDictEqual(
            self.private_keys,
            keys,
        )

        self.secrets.get.assert_called_with('/path/to/private', silent_if_not_found=True)

    def test_fetch_and_check_keys_success_empty(self):
        secrets = SimpleNamespace(get=MagicMock(return_value=None), )
        test = CreateKey('di', secrets, 'datetime', 'uuid')
        keys = test.fetch_and_check_keys('/path/to/private')

        self.assertDictEqual(
            {},
            keys,
        )

    def test_fetch_and_check_keys_not_json(self):
        secrets = SimpleNamespace(get=MagicMock(return_value='sup'), )
        test = CreateKey('di', secrets, 'datetime', 'uuid')

        with self.assertRaises(ValueError) as context:
            keys = test.fetch_and_check_keys('/path/to/private')
        self.assertEquals(
            "I fetched the key data from '/path/to/private'.  It should have been a JSON encoded object but it isn't JSON.  Sorry :(",
            str(context.exception)
        )

    def test_fetch_and_check_keys_wrong_type(self):
        secrets = SimpleNamespace(get=MagicMock(return_value='[]'), )
        test = CreateKey('di', secrets, 'datetime', 'uuid')

        with self.assertRaises(ValueError) as context:
            keys = test.fetch_and_check_keys('/path/to/private')
        self.assertEquals(
            "The key data stored in '/path/to/private' should have been a dictionary but instead was a 'list'",
            str(context.exception)
        )

    def test_check_consistencies_extra_private_key(self):
        test = CreateKey('di', 'secrets', 'datetime', 'uuid')

        with self.assertRaises(ValueError) as context:
            test.check_for_inconsistencies({'key_id_1': 1, 'key_id_2': 2}, {'key_id_1': 1})
        self.assertEquals(
            "There are some private keys that don't have corresponding public keys.  Those are: 'key_id_2'.  You'll have to manually restore the missing key or delete the extra key.",
            str(context.exception)
        )

    def test_check_consistencies_extra_public_key(self):
        test = CreateKey('di', 'secrets', 'datetime', 'uuid')

        with self.assertRaises(ValueError) as context:
            test.check_for_inconsistencies({'key_id_1': 1}, {'key_id_1': 1, 'key_id_2': 2})
        self.assertEquals(
            "There are some public keys that don't have corresponding private keys.  Those are: 'key_id_2'.  You'll have to manually restore the missing key or delete the extra key.",
            str(context.exception)
        )
