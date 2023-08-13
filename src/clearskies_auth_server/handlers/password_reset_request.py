import secrets
import inspect
from clearskies.handlers.exceptions import InputError
from clearskies.handlers.base import Base
from clearskies.column_types import Audit


class PasswordResetRequest(Base):
    _configuration_defaults = {
        "user_model_class": "",
        "username_column_name": "email",
        "email_column_name": "email",
        "reset_key_lifetime_seconds": 86400,
        "reset_key_column_name": "reset_key",
        "reset_expiration_column_name": "reset_key_expiration",
        "where": None,
        "input_error_callable": None,
        "audit": True,
        "audit_column_name": "audit",
        "audit_action_name": "request_password_reset",
        "users": None,
    }

    _required_configurations = [
        "user_model_class",
    ]

    def __init__(self, di, datetime):
        super().__init__(di)
        self._columns = None
        self._datetime = datetime

    def _check_configuration(self, configuration):
        super()._check_configuration(configuration)
        error_prefix = "Invalid configuration for handler " + self.__class__.__name__ + ":"
        for key in self._required_configurations:
            if not configuration.get(key):
                raise ValueError(f"{error_prefix} missing required configuration '{key}'")

        user_model_class = configuration.get("user_model_class")
        if not inspect.isclass(user_model_class):
            raise ValueError(
                f"{error_prefix} 'user_model_class' should be a model class, but instead it is a '"
                + type(user_model_class)
                + "'"
            )
        if not getattr(user_model_class, "where"):
            raise ValueError(
                f"{error_prefix} 'user_model_class' should be a clearskies model class, but instead it is a '"
                + user_model_class.__name__
                + "'"
            )
        users = self._di.build(user_model_class)
        self._columns = users.columns()

        columns_to_check = [
            "username_column_name",
            "email_column_name",
            "reset_key_column_name",
            "reset_expiration_column_name",
        ]
        for config_name in columns_to_check:
            is_default = config_name not in configuration
            column_name = configuration.get(config_name, self._configuration_defaults.get(config_name))
            if column_name not in self._columns:
                if is_default:
                    raise ValueError(
                        f"{error_prefix} the configuration setting, '{config_name}' is not set and the default column name, '{column_name}', does not exist in the user model '{user_model_class.__name__}'"
                    )
                else:
                    raise ValueError(
                        f"{error_prefix} the provided column name for {config_name}, '{column_name}', does not exist in the user model '{user_model_class.__name__}'"
                    )
        lifetime = configuration.get("reset_key_lifetime_seconds")
        if lifetime and not isinstance(lifetime, int):
            raise ValueError(f"{error_prefix} the provided value for 'reset_key_lifetime_seconds' must be an integer.")

        if configuration.get("audit"):
            audit_column_name = configuration.get("audit_column_name")
            if audit_column_name not in self._columns:
                raise ValueError(
                    f"{error_prefix} 'audit_column_name' is '{audit_column_name}' but this column does not exist in the user model class, '{user_model_class.__name__}'"
                )
            if not isinstance(self._columns[audit_column_name], Audit):
                raise ValueError(
                    f"{error_prefix} 'audit_column_name' is '{audit_column_name}' but this column is not an audit column for the user model class, '{user_model_class.__name__}'"
                )

        for callable_name in ["where", "input_error_callable"]:
            config = configuration.get(callable_name)
            if config and not callable(config):
                raise ValueError(f"{error_prefix} '{callable_name}' must be a callable but it is a " + type(config))

    def _get_audit_column(self, columns):
        audit_column = None
        for column in columns.values():
            if not isinstance(column, Audit):
                continue
            return column
        return None

    def apply_default_configuration(self, configuration):
        if not configuration.get("audit_column_name") and ("audit" not in configuration or configuration["audit"]):
            configuration["audit_column_name"] = self._get_audit_column(self._columns).name
        return super().apply_default_configuration(configuration)

    @property
    def users(self):
        return self._di.build(self.configuration("user_model_class"), cache=True)

    def handle(self, input_output):
        request_data = self.request_data(input_output)
        input_errors = self._find_input_errors(self.users, request_data, input_output)
        if input_errors:
            raise InputError(input_errors)

        username_column_name = self.configuration("username_column_name")
        users = self.users
        if self.configuration("where"):
            users = self._di.call_function(
                self.configuration("where"),
                users=users,
                input_output=input_output,
                request_data=request_data,
                routing_data=input_output.routing_data(),
            )
        user = self.users.find(f"{username_column_name}=" + request_data[username_column_name])

        # no user found.  Don't return data since that gives away if the user exists in the system.
        if not user.exists:
            return self.success(input_output, {})

        self.audit(user, self.configuration("audit_action_name"))
        user.save(
            {
                self.configuration("reset_key_column_name"): secrets.token_urlsafe(nbytes=32),
                self.configuration("reset_expiration_column_name"): self._datetime.datetime.now(
                    self._datetime.timezone.utc
                )
                + self._datetime.timedelta(seconds=self.configuration("reset_key_lifetime_seconds")),
            }
        )

        return self.success(input_output, {})

    def request_data(self, input_output, required=True):
        # make sure we don't drop any data along the way, because the input validation
        # needs to return an error for unexpected data.
        column_map = {
            self.configuration("username_column_name"): self.auto_case_column_name(
                self.configuration("username_column_name"), True
            ),
        }
        mapped_data = {}
        for key, value in input_output.request_data(required=required).items():
            mapped_data[column_map.get(key, key)] = value
        return mapped_data

    def _find_input_errors(self, model, request_data, input_output):
        input_errors = {}
        allowed_column_names = [
            self.configuration("username_column_name"),
        ]
        for extra_column in set(request_data.keys()) - set(allowed_column_names):
            input_errors[extra_column] = "Input column '{extra_column}' is not an allowed column."
        for column_name in allowed_column_names:
            input_errors = {
                **input_errors,
                **self._columns[column_name].input_errors(model, request_data),
            }
        input_error_callable = self.configuration("input_error_callable")
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
                    "The input error callable, '"
                    + str(input_error_callable)
                    + "', did not return a dictionary as required"
                )
            input_errors = {
                **input_errors,
                **more_input_errors,
            }
        return input_errors

    def audit(self, user, action_name, data=None):
        if not self.configuration("audit"):
            return
        self._columns[self.configuration("audit_column_name")].record(user, action_name, data=None)
