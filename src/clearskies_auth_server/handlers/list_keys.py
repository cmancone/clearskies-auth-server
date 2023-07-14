from jwcrypto import jwk
import json

from .key_base import KeyBase


class ListKeys(KeyBase):
    def handle(self, input_output):
        # fetch the old keys
        private_keys = self.fetch_and_check_keys(self.configuration("path_to_private_keys"))
        public_keys = self.fetch_and_check_keys(self.configuration("path_to_public_keys"))
        self.check_for_inconsistencies(private_keys, public_keys)

        keys = [
            {
                "id": key["kid"],
                "algorithm": key["alg"],
                "issue_date": key["issue_date"],
            }
            for key in private_keys.values()
        ]
        return self.success(input_output, keys)
