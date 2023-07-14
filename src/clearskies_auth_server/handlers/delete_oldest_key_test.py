import json
import unittest
from unittest.mock import MagicMock, call
from types import SimpleNamespace
from jwcrypto import jwk
from .key_base_test import KeyBaseTest
from .delete_oldest_key import DeleteOldestKey
from clearskies.contexts import test


class DeleteOldestKeyTest(KeyBaseTest):
    def test_never_delete_the_last_key(self):
        delete_oldest_key = test(
            {
                "handler_class": DeleteOldestKey,
                "handler_config": {
                    "path_to_private_keys": "/path/to/private",
                    "path_to_public_keys": "/path/to/public",
                },
            },
            bindings={"secrets": self.secrets},
        )
        result = delete_oldest_key(routing_data={"key_id": self.key_id})
        self.assertEquals(200, result[1])
        self.assertEquals(
            "I'm cowardly refusing to delete the last key.  Sorry.",
            result[0]["input_errors"],
        )

    def test_delete_oldest(self):
        private_keys = {**self.private_keys, "another_key_id": {"kid": "another_key_id", "issue_date": "0"}}
        public_keys = {**self.public_keys, "another_key_id": {"kid": "another_key_id", "issue_date": "0"}}

        fetch_keys = MagicMock()
        fetch_keys.side_effect = [json.dumps(private_keys), json.dumps(public_keys)]
        secrets = SimpleNamespace(
            get=fetch_keys,
            upsert=MagicMock(),
        )

        delete_oldest_key = test(
            {
                "handler_class": DeleteOldestKey,
                "handler_config": {
                    "path_to_private_keys": "/path/to/private",
                    "path_to_public_keys": "/path/to/public",
                },
            },
            bindings={"secrets": secrets},
        )

        result = delete_oldest_key()
        self.assertEquals(200, result[1])
        self.assertEquals(
            {"id": "another_key_id"},
            result[0]["data"],
        )

        upsert_calls = secrets.upsert.call_args_list

        self.assertEquals(
            "/path/to/private",
            upsert_calls[0].args[0],
        )
        # we're just going to check the keys (:shh:)
        saved_keys = list(json.loads(upsert_calls[0].args[1]).keys())
        self.assertEquals([self.key_id], saved_keys)

        self.assertEquals(
            "/path/to/public",
            upsert_calls[1].args[0],
        )

        saved_keys = list(json.loads(upsert_calls[1].args[1]).keys())
        self.assertEquals([self.key_id], saved_keys)
