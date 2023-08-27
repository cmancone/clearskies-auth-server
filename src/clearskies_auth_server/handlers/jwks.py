from jwcrypto import jwk
import json

from .key_base import KeyBase


class Jwks(KeyBase):
    def handle(self, input_output):
        public_keys = self.fetch_and_check_keys(self.configuration("path_to_public_keys"))

        keys = [
            {
                "kid": key["kid"],
                "use": key["use"],
                "e": key["e"],
                "n": key["n"],
                "kty": key["kty"],
                "alg": key["alg"],
            }
            for key in public_keys.values()
        ]

        return self.respond_unstructured(input_output, {"keys": keys}, 200)
