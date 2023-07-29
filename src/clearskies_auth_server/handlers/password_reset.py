import secrets
import inspect
from clearskies.handlers.exceptions import InputError
from clearskies.handlers import Update
from clearskies.column_types import Audit


class PasswordReset(Update):
    _configuration_defaults = {
        "user_model_class": "",
        "password_column_name": "password",
        "reset_key_column_name": "reset_key",
        "reset_expiration_column_name": "reset_key_expiration",
        "reset_key_source": "routing_data",
        "reset_key_source_key_name": "reset_key",
        "model_class": "",
        "column_overrides": None,
        "columns": None,
        "writeable_columns": None,
        "readable_columns": None,
        "where": [],
        "input_error_callable": None,
        "audit": True,
        "audit_column_name": None,
        "audit_action_name_successful_reset": "password_reset",
    }

    _required_configurations = [
        "user_model_class",
    ]

    def __init__(self, di, datetime):
        super().__init__(di)
        self._columns = None
        self._datetime = datetime

    def _check_configuration(self, configuration):
        user_model_class = configuration.get("user_model_class")
        super()._check_configuration(
            {
                **{
                    "model_class": user_model_class,
                    "writeable_columns": [
                        configuration.get(
                            "password_column_name", self._configuration_defaults.get("password_column_name")
                        )
                    ],
                },
                **configuration,
            }
        )
        error_prefix = "Configuration error for %s:" % (self.__class__.__name__)
        if "reset_key_source" in configuration and configuration["reset_key_source"] not in ["routing_data"]:
            raise ValueError(f"{error_prefix} 'reset_key_source' must be 'routing_data'")

        columns_to_check = [
            "password_column_name",
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
        return super().apply_default_configuration(
            {
                **{
                    "model_class": configuration.get("user_model_class"),
                    "writeable_columns": [
                        configuration.get(
                            "password_column_name", self._configuration_defaults.get("password_column_name")
                        )
                    ],
                },
                **configuration,
            }
        )

    @property
    def users(self):
        return self._di.build(self.configuration("user_model_class"), cache=True)

    def get_model_id(self, input_output, input_data):
        routing_data = input_output.routing_data()
        reset_key_column_name = self.configuration("reset_key_column_name")
        reset_key_source_key_name = self.configuration("reset_key_source_key_name")
        reset_expiration_column_name = self.configuration("reset_expiration_column_name")
        if not routing_data.get(reset_key_source_key_name):
            raise ValueError(
                "Error with PasswordReset handler: the reset key wasn't found in the routing data, which usually means I'm misconfigured"
            )

        user = self.users.find(f"{reset_key_column_name}=" + routing_data.get(reset_key_source_key_name))
        if not user.exists:
            return None

        # make sure it hasn't expired
        expiration = user.get(reset_expiration_column_name)
        now = (
            self._datetime.datetime.now(self._datetime.timezone.utc)
            if expiration.tzinfo
            else self._datetime.datetime.now()
        )
        if expiration < now:
            return None

        return user.get(self.users.id_column_name)

    def documentation(self):
        return self._documentation(
            description="Reset the user's password",
            response_description=f"Success or Failure",
            include_id_in_path=False,
        )
