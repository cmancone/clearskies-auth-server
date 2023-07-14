from jwcrypto import jwk
import json

from .key_base import KeyBase


class CreateKey(KeyBase):
    _uuid = None

    def __init__(self, di, secrets, datetime, uuid):
        super().__init__(di, secrets, datetime)
        self._uuid = uuid

    def handle(self, input_output):
        # fetch the old keys
        private_keys = self.fetch_and_check_keys(self.configuration("path_to_private_keys"))
        public_keys = self.fetch_and_check_keys(self.configuration("path_to_public_keys"))
        self.check_for_inconsistencies(private_keys, public_keys)

        # make a new key
        key_id = str(self._uuid.uuid4())
        key = jwk.JWK.generate(
            kty=self.configuration("key_type"),
            size=self.configuration("key_size"),
            kid=key_id,
            alg=self.configuration("algorithm"),
            use="sig",
        )

        # and add it to our dictionaries
        private_keys[key_id] = {
            **json.loads(key.export_private()),
            "issue_date": self._datetime.datetime.now(self._datetime.timezone.utc).isoformat(),
        }
        public_keys[key_id] = {
            **json.loads(key.export_public()),
            "issue_date": self._datetime.datetime.now(self._datetime.timezone.utc).isoformat(),
        }

        self.save_keys(self.configuration("path_to_private_keys"), private_keys)
        self.save_keys(self.configuration("path_to_public_keys"), public_keys)

        return self.success(input_output, {"id": key_id})
