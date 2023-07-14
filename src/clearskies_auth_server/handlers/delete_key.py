from jwcrypto import jwk
import json

from clearskies.handlers.exceptions import NotFound, InputError
from .key_base import KeyBase


class DeleteKey(KeyBase):
    def handle(self, input_output):
        # fetch the old keys
        private_keys = self.fetch_and_check_keys(self.configuration("path_to_private_keys"))
        public_keys = self.fetch_and_check_keys(self.configuration("path_to_public_keys"))
        self.check_for_inconsistencies(private_keys, public_keys)

        key_id = input_output.routing_data().get("key_id")
        if key_id not in private_keys:
            raise NotFound(f"Key '{key_id}' not found")
        if len(private_keys) == 1:
            raise InputError({"id": "I'm cowardly refusing to delete the last key.  Sorry."})

        private_keys = {key: value for (key, value) in private_keys.items() if key != key_id}
        public_keys = {key: value for (key, value) in public_keys.items() if key != key_id}

        self.save_keys(self.configuration("path_to_private_keys"), private_keys)
        self.save_keys(self.configuration("path_to_public_keys"), public_keys)

        return self.success(input_output, {"id": key_id})
