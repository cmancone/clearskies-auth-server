import clearskies
import datetime
import json


class JwksDirect(clearskies.authentication.JWKS):
    _path_to_public_keys = None

    def __init__(self, environment, secrets, jose_jwt):
        # our base requires the requests library but we're going to replace all usages of it,
        # so we're going to inject in some gibberish instead, which will cause things to crash
        # if the base tries to use the requests library (which is actually good, because it
        # shouldn't, so we want any attempted usage to just fail).
        super().__init__(environment, "not-requests", jose_jwt)
        self._secrets = secrets

    def configure(
        self,
        path_to_public_keys=None,
        algorithms=None,
        audience=None,
        issuer=None,
        documentation_security_name=None,
        jwks_cache_time=86400,
    ):
        self._path_to_public_keys = path_to_public_keys
        self._audience = audience
        self._issuer = issuer
        self._jwks_cache_time = jwks_cache_time
        if not self._path_to_public_keys:
            raise ValueError("Must provide 'path_to_public_keys' when using JWKS authentication")
        self._algorithms = ["RS256"] if algorithms is None else algorithms
        self._documentation_security_name = documentation_security_name

    def _get_jwks(self):
        now = datetime.datetime.now()
        if self._jwks is None or ((now - self._jwks_fetched).total_seconds() > self._jwks_cache_time):
            key_data = json.loads(self._secrets.get(self._path_to_public_keys))
            self._jwks = {
                "keys": [
                    {
                        "kid": key["kid"],
                        "use": key["use"],
                        "e": key["e"],
                        "n": key["n"],
                        "kty": key["kty"],
                        "alg": key["alg"],
                    }
                    for key in key_data.values()
                ]
            }
            self._jwks_fetched = now

        return self._jwks
