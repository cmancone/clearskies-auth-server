import json
from jwcrypto import jwk, jwt
from clearskies.handlers.exceptions import InputError
from .key_base import KeyBase
class PasswordLogin(KeyBase):

    _configuration_defaults = {
        'user_model_class': '',
        'username_column_name': 'email',
        'password_column_name': 'password',
        'jwt_lifetime_seconds': 86400,
        'issuer': '',
        'audience': '',
        'path_to_private_keys': '',
        'key_cache_duration': 7200,
        'claims_callable': None,
        'claims_column_names': None,
        'input_error_callable': None,
        'users': None,
    }

    _required_configurations = [
        'issuer',
        'audience',
        'user_model_class',
        'username_column_name',
        'password_column_name',
        'path_to_private_keys',
        'key_cache_duration',
    ]

    def __init__(self, di, datetime):
        self.di = di
        self.datetime = datetime
        self._columns = None

    def _check_configuration(self, configuration):
        super()._check_configuration(configuration)
        error_prefix = "Invalid configuation for handler " + self.__class__.__name__ + ":"
        for key in self._required_configurations:
            if not configuration.get(key):
                raise ValueError(f"{error_prefix} missing required configuration '{key}'")
        if 'claims_callable' in configuration and not callable(configuration.get('claims_callable')):
            raise ValueError(f"{error_prefix} the provided 'claims_callable' configuration is not actually callable.")
        if 'input_error_callable' in configuration and not callable(configuration.get('input_error_callable')):
            raise ValueError(
                f"{error_prefix} the provided 'input_error_callable' configuration is not actually callable."
            )

        user_model_class = self.di.build(configuration.get('user_model_class'))
        if not inspect.isclass(user_model_class):
            raise ValueError(
                f"{error_prefix} 'user_model_class' should be a model class, but instead it is a '" +
                type(user_model_class) + "'"
            )
        if not getattr(user_model_class, 'where'):
            raise ValueError(
                f"{error_prefix} 'user_model_class' should be a clearskies model class, but instead it is a '" +
                user_model_class.__name__ + "'"
            )
        self._columns = user_model_class.columns()
        username_column_name = configuration.get('username_column_name')
        password_column_name = configuration.get('password_column_name')
        if username_column_name not in columns:
            raise ValueError(
                f"{error_prefix} the provided username column, '{username_column_name}', does not exist in the user model '{user_model_class.__name__}'"
            )
        if not columns[username_column_name].is_required:
            raise ValueError(
                f"{error_prefix} the provided username column, '{username_column_name}', in model '{user_model_class.__name__}' must be a required column."
            )
        if password_column_name not in columns:
            raise ValueError(
                f"{error_prefix} the provided password column, '{password_column_name}', does not exist in the user model '{user_model_class.__name__}'"
            )
        if not columns[password_column_name].is_required:
            raise ValueError(
                f"{error_prefix} the provided password column, '{password_column_name}', in model '{user_model_class.__name__}' must be a required column."
            )
        if not hasattr(columns[password_column_name], 'validate_password'):
            raise ValueError(
                f"{error_prefix} the provided password column, '{password_column_name}', in model '{user_model_class.__name__}' does not implement the required 'validate_password' method.  You should double check to make sure it is using the 'clearskies_auth_server.columns.password column' type."
            )

        if not configuration.get('claims_callable') and not configuration.get('claims_column_names'):
            raise ValueError(
                f"{error_prefix} you set both 'claims_callable' and 'claims_column_names' but only one can be set."
            )

        if configuration.get('claims_column_names'):
            claims_column_names = configuration['claims_column_names']
            if not isinstance(claims_column_names, list):
                raise ValueError(
                    f"{error_prefix} 'claims_column_names' should be a list of column names, but instead has type " +
                    type(claims_column_names)
                )
            for column_name in claims_column_names:
                if column_name not in self._columns:
                    raise ValueError(
                        f"{error_prefix} a configured claim column, '{column_name}' does not exist in the user model"
                    )
                if not self._columns[column_name].is_readable:
                    raise ValueError(
                        f"{error_prefix} a configured claim column, '{column_name}' is not readable and so cannot be used in the claims"
                    )

    @property
    def users(self):
        return self.di.build(self.configuration('user_model_class'), cache=True)

    def handle(self, input_output):
        request_data = self.request_data(input_output)
        input_errors = self._find_input_errors(self.users, request_data, input_output)
        if input_errors:
            raise InputError(input_errors)

        username_column_name = self.config('username_column_name')
        password_column_name = self.config('password_column_name')
        password_column = self._columns[password_column_name]
        user = self.users.where(f'{username_column_name}=' + request_data[username_column_name])
        if not user.exists:
            return self.error(self, input_output, "Invalid username/password combination", 404)

        if not password_column.validate_password(user, request_data[password_column_name]):
            return self.error(self, input_output, "Invalid username/password combination", 404)

        signing_key = self.get_youngest_private_key(self.config('path_to_private_keys'), as_json=False)
        jwt_claims = self.get_jwt_claims(user)
        token = jwt.JWT(header={"alg": "RS256", "typ": "JWT"}, claims=jwt_claims)
        token.make_signed_token(signing_key)

        return input_output.respond({
            'token': token.serialize(),
            'expires_at': jwt_claims['expires_at'],
        }, 200)

    def request_data(self, input_output, required=True):
        # make sure we don't drop any data along the way, because the input validation
        # needs to return an error for unexpected data.
        column_map = {
            self.config('username_column_name'): self.auto_case_column_name(self.config('username_column_name'), True),
            self.config('password_column_name'): self.auto_case_column_name(self.config('password_column_name'), True),
        }
        mapped_data = {}
        for (key, value) in input_output.request_data(required=required):
            mapped_data[column_map.get(key, key)] = value
        return mapped_data

    def _find_input_errors(self, model, request_data, input_output):
        input_errors = {}
        allowed_column_names = [
            self.config('username_column_name'),
            self.config('password_column_name'),
        ]
        for extra_column in set(request_data.keys()) - set(allowed_column_names):
            input_errors[extra_column] = "Input column '{extra_column}' is not an allowed column."
        for column_name in allowed_column_names:
            input_errors = {
                **input_errors,
                **self._columns[column_name].input_errors(model, request_data),
            }
        input_error_callable = self.configuration('input_error_callable')
        if input_error_callable:
            more_input_errors = self._di.call_function(
                input_error_callable,
                input_data=request_data,
                request_data=request_data,
                input_output=input_output,
                routing_data=input_output.routing_data(),
                authorization_data=input_output.get_authorization_data(),
            )
            if type(more_input_errors) != dict:
                raise ValueError(
                    "The input error callable, '" + str(input_error_callable) +
                    "', did not return a dictionary as required"
                )
            input_errors = {
                **input_errors,
                **more_input_errors,
            }
        return input_errors

    def get_jwt_claims(self, user):
        if self.configuration('input_error_callable'):
            claims = self._di.call_function(user=user)
        else:
            claims = {
                claim_column: user.get(claim_column)
                for claim_column in self.configuration('claims_column_names')
            }

        now = self.datetime.datetime.now(self.datetime.timezone.utc)
        claims = {
            'aud': self.configuration('audience'),
            'iss': self.configuration('issuer'),
            'exp': int((now + datetime.timedelta(seconds=self.configuration('jwt_lifetime_seconds'))).timestamp()),
            **claims,
            'iat': int(now.timestamp()),
        }
