from jwcrypto import jwk
import json

from clearskies.handlers.base import Base
from clearskies.handlers.exceptions import InputError, ClientError, NotFound
from .. import autodoc
class GenerateKeys(Base):
    _secrets = None
    _uuid = None

    _configuration_defaults = {
        'path_to_public_key': '',
        'path_to_private_key': '',
        'algorithm': 'RSA256',
        'key_type': 'RSA',
        'key_size': 2048,
    }

    def __init__(self, di, secrets, uuid):
        self._secrets = secrets
        self._uuid = uuid
        super().__init__(di)

    def handle(self, input_output):
        key = jwk.JWK.generate(
            kty=self.configuration('key_type'),
            size=self.configuration('key_size'),
            kid=str(self._uuid.uuid4()),
            alg=self.configuration('algorithm'),
            use='sig',
        )
        self._secrets.upsert(self.config('path_to_public_key'), key.export_public())
        self._secrets.upsert(self.config('path_to_private_key'), key.export_private())
        return self.success(input_output, response)

    def _check_configuration(self, configuration):
        super()._check_configuration(configuration)
        error_prefix = 'Configuration error for %s:' % (self.__class__.__name__)
        for config_name in ['path_to_private_key', 'path_to_public_key']:
            if not configuration.get(config_name):
                raise ValueError(f"{error_prefix} the configuration value '{config_name}' is required but missing.")
        if configuration.get('algorithm') != 'RSA256':
            raise ValueError('Currently only RSA256 is supported for the algorithm.')
        if configuration.get('key_type') != 'RSA':
            raise ValueError('Currently only RSA keys are supported.')
