import json
from clearskies.handlers.base import Base as HandlerBase
class KeyBase(HandlerBase):
    _secrets = None
    _datetime = None

    _configuration_defaults = {
        'path_to_public_keys': '',
        'path_to_private_keys': '',
        'algorithm': 'RSA256',
        'key_type': 'RSA',
        'key_size': 2048,
    }

    def __init__(self, di, secrets, datetime):
        super().__init__(di)
        self._secrets = secrets
        self._datetime = datetime

    def _check_configuration(self, configuration):
        super()._check_configuration(configuration)
        error_prefix = 'Configuration error for %s:' % (self.__class__.__name__)
        for config_name in ['path_to_private_keys', 'path_to_public_keys']:
            if not configuration.get(config_name):
                raise ValueError(f"{error_prefix} the configuration value '{config_name}' is required but missing.")
        algorithm = configuration.get('algorithm')
        if algorithm and algorithm != 'RSA256':
            raise ValueError('Currently only RSA256 is supported for the algorithm.')
        key_type = configuration.get('key_type')
        if key_type and key_type != 'RSA':
            raise ValueError('Currently only RSA keys are supported.')

    def fetch_and_check_keys(self, path):
        raw_data = self._secrets.get(path, silent_if_not_found=True)
        if not raw_data:
            return {}

        try:
            key_data = json.loads(raw_data)
        except json.JSONDecodeError as e:
            raise ValueError(
                f"I fetched the key data from '{path}'.  It should have been a JSON encoded object but it isn't JSON.  Sorry :("
            )

        actual_type = type(key_data)
        if actual_type != dict:
            raise ValueError(
                f"The key data stored in '{path}' should have been a dictionary but instead was a '{actual_type.__name__}'"
            )

        # that's as far as we're going to get for now.
        return key_data

    def check_for_inconsistencies(self, private_keys, public_keys):
        """
        Checks that the public and private keys have the same set of keys.

        This exists because the private keys are stored in separate locations, so it's
        good to have a quick sanity check that they haven't grown out of sync.

        They are stored separately so that you can use separate permission controls
        for the private and public keys (if desired).

        The main thing we'll check for is to confirm that they have the same key ids
        """
        # the key ids are also the key in the dictionary
        private_key_ids = set(private_keys.keys())
        public_key_ids = set(public_keys.keys())
        extra_private_keys = private_key_ids - public_key_ids
        extra_public_keys = public_key_ids - private_key_ids
        if extra_private_keys:
            raise ValueError(
                "There are some private keys that don't have corresponding public keys.  Those are: '" +
                "', '".join(extra_private_keys) +
                "'.  You'll have to manually restore the missing key or delete the extra key."
            )
        if extra_public_keys:
            raise ValueError(
                "There are some public keys that don't have corresponding private keys.  Those are: '" +
                "', '".join(extra_public_keys) +
                "'.  You'll have to manually restore the missing key or delete the extra key."
            )

    def save_keys(self, path, keys):
        self._secrets.upsert(path, json.dumps(keys))
