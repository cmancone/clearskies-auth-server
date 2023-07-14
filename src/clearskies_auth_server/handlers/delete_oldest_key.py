from jwcrypto import jwk
import json

from clearskies.handlers.exceptions import InputError
from .key_base import KeyBase


class DeleteOldestKey(KeyBase):
    def handle(self, input_output):
        # fetch the old keys
        private_keys = self.fetch_and_check_keys(self.configuration("path_to_private_keys"))
        public_keys = self.fetch_and_check_keys(self.configuration("path_to_public_keys"))
        self.check_for_inconsistencies(private_keys, public_keys)

        if len(private_keys) == 1:
            raise InputError("I'm cowardly refusing to delete the last key.  Sorry.")
        key_id = min(private_keys, key=lambda key_id: private_keys[key_id]["issue_date"])

        private_keys = {key: value for (key, value) in private_keys.items() if key != key_id}
        public_keys = {key: value for (key, value) in public_keys.items() if key != key_id}

        self.save_keys(self.configuration("path_to_private_keys"), private_keys)
        self.save_keys(self.configuration("path_to_public_keys"), public_keys)

        return self.success(input_output, {"id": key_id})
