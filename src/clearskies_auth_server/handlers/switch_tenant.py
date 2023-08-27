import inspect
import json
from jwcrypto import jwk, jwt
from clearskies.handlers.exceptions import InputError
from clearskies.column_types import Audit
from .key_base import KeyBase
import datetime


class SwitchTenant(KeyBase):
    _configuration_defaults = {
        "user_model_class": "",
        "tenant_id_column_name": "",
        "tenant_id_source": "",
        "tenant_id_source_key_name": "",
        "username_column_name": "email",
        "username_key_name_in_authorization_data": "email",
        "issuer": "",
        "audience": "",
        "path_to_private_keys": "",
        "path_to_public_keys": "",
        "key_cache_duration": 7200,
        "can_switch_callable": None,
        "claims_callable": None,
        "claims_column_names": None,
        "audit": True,
        "audit_column_name": None,
        "audit_action_name_successful_login": "login",
        "users": None,
    }

    _required_configurations = [
        "issuer",
        "audience",
        "user_model_class",
        "path_to_private_keys",
        "path_to_public_keys",
        "tenant_id_column_name",
        "tenant_id_source",
        "tenant_id_source_key_name",
    ]

    def __init__(self, di, secrets, datetime):
        super().__init__(di, secrets, datetime)
        self._columns = None

    def _check_configuration(self, configuration):
        super()._check_configuration(configuration)
        error_prefix = "Invalid configuration for handler " + self.__class__.__name__ + ":"
        for key in self._required_configurations:
            if not configuration.get(key):
                raise ValueError(f"{error_prefix} missing required configuration '{key}'")
        if "claims_callable" in configuration and not callable(configuration.get("claims_callable")):
            raise ValueError(f"{error_prefix} the provided 'claims_callable' configuration is not actually callable.")
        if "input_error_callable" in configuration and not callable(configuration.get("input_error_callable")):
            raise ValueError(
                f"{error_prefix} the provided 'input_error_callable' configuration is not actually callable."
            )
        if "can_switch_callable" in configuration and not callable(configuration.get("can_switch_callable")):
            raise ValueError(
                f"{error_prefix} the provided 'can_switch_callable' configuration is not actually callable."
            )

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
        user_model = self._di.build(user_model_class)
        temporary_columns = user_model.columns()
        username_column_name = configuration.get("username_column_name", "email")
        password_column_name = configuration.get("password_column_name", "password")
        if username_column_name not in temporary_columns:
            raise ValueError(
                f"{error_prefix} the provided username column, '{username_column_name}', does not exist in the user model '{user_model_class.__name__}'"
            )
        if not temporary_columns[username_column_name].is_required:
            raise ValueError(
                f"{error_prefix} the provided username column, '{username_column_name}', in model '{user_model_class.__name__}' must be a required column."
            )
        if password_column_name not in temporary_columns:
            raise ValueError(
                f"{error_prefix} the provided password column, '{password_column_name}', does not exist in the user model '{user_model_class.__name__}'"
            )
        if not temporary_columns[password_column_name].is_required:
            raise ValueError(
                f"{error_prefix} the provided password column, '{password_column_name}', in model '{user_model_class.__name__}' must be a required column."
            )
        if not hasattr(temporary_columns[password_column_name], "validate_password"):
            raise ValueError(
                f"{error_prefix} the provided password column, '{password_column_name}', in model '{user_model_class.__name__}' does not implement the required 'validate_password' method.  You should double check to make sure it is using the 'clearskies_auth_server.columns.password column' type."
            )

        # we're getting columns twice, which is inefficient.  The reason why is because, for the columns object we actually use,
        # we need to set an override on the password column and set `for_login` to True.  I don't want to do this when I initially
        # fetch the columns above because, if the user passed in the wrong name for the password column, this would result in weird
        # and confusing errors.  Therefore, we get the columns above without any overrides, do the first round of user input validation, and then
        # we re-fetch the columns and set our overrides.
        self._columns = user_model.columns(overrides={password_column_name: {"for_login": True}})

        if configuration.get("claims_callable") and configuration.get("claims_column_names"):
            raise ValueError(
                f"{error_prefix} you set both 'claims_callable' and 'claims_column_names' but only one can be set."
            )
        if not configuration.get("claims_callable") and not configuration.get("claims_column_names"):
            raise ValueError(
                f"{error_prefix} you must set either 'claims_callable' or 'claims_column_names' but neither was set."
            )

        if configuration.get("claims_column_names"):
            claims_column_names = configuration["claims_column_names"]
            if not isinstance(claims_column_names, list):
                raise ValueError(
                    f"{error_prefix} 'claims_column_names' should be a list of column names, but instead has type "
                    + type(claims_column_names)
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

        if configuration.get("tenant_id_column_name"):
            tenant_id_column_name = configuration.get("tenant_id_column_name")
            if tenant_id_column_name not in self._columns:
                raise ValueError(
                    f"{error_prefix} 'tenant_id_column_name' is '{tenant_id_column_name}' but this column does not exist in the user model class, '{user_model_class.__name__}'"
                )
            for config_name in ["tenant_id_source", "tenant_id_source_key_name"]:
                if not configuration.get(config_name):
                    raise ValueError(
                        f"{error_prefix} 'tenant_id_column_name' is specified, which enables multi-tenant login. However, this also requires you to define '{config_name}', which is not defined."
                    )
            if configuration.get("tenant_id_source") not in ["routing_data"]:
                raise ValueError(
                    f"{error_prefix} 'tenant_id_source must be set to 'routing_data', but is something else."
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
        return super().apply_default_configuration(configuration)

    @property
    def users(self):
        return self._di.build(self.configuration("user_model_class"), cache=True)

    def get_tenant_id(self, input_output):
        source = self.configuration("tenant_id_source")
        if source == "routing_data":
            routing_data = input_output.routing_data()
            return routing_data.get(self.configuration("tenant_id_source_key_name"))

    def get_username(self, authorization_data):
        return authorization_data.get(self.configuration("username_key_name_in_authorization_data"))

    def handle(self, input_output):
        authorization_data = input_output.get_authorization_data()
        tenant_id = self.get_tenant_id(input_output)
        if not tenant_id:
            return self.error(input_output, "Invalid tenant", 404)
        username = self.get_username(authorization_data)
        if not username:
            return self.error(input_output, "Invalid user", 404)
        can_switch_callable = self.configuration("can_switch_callable")
        if can_switch_callable:
            allowed = self._di.call_function(
                can_switch_callable,
                tenant_id=tenant_id,
                username=username,
                request_data=input_output.request_data(required=False),
                input_output=input_output,
                **input_output.routing_data(),
                **input_output.context_specifics(),
            )
            if not allowed:
                return self.error(input_output, "Invalid user + tenant", 404)

        username_column_name = self.configuration("username_column_name")
        tenant_id_column_name = self.configuration("tenant_id_column_name")

        user = (
            self.users.where(f"{tenant_id_column_name}={tenant_id}").where(f"{username_column_name}={username}").first()
        )

        # no user found
        if not user.exists:
            return self.error(input_output, "Invalid user + tenant", 404)

        self.audit(user, self.configuration("audit_action_name_successful_login"))
        signing_key = self.get_youngest_private_key(self.configuration("path_to_private_keys"), as_json=False)
        # use the old expiration time, otherwise users can just automatically extend their session life
        jwt_claims = self.get_jwt_claims(user, authorization_data["exp"])
        token = jwt.JWT(header={"alg": "RS256", "typ": "JWT", "kid": signing_key["kid"]}, claims=jwt_claims)
        token.make_signed_token(signing_key)

        return self.respond_unstructured(
            input_output,
            {
                "token": token.serialize(),
                "expires_at": jwt_claims["exp"],
            },
            200,
        )

    def get_jwt_claims(self, user, exp):
        if self.configuration("claims_callable"):
            claims = self._di.call_function(user=user)
        else:
            claims = {
                claim_column: user.get(claim_column) for claim_column in self.configuration("claims_column_names")
            }

        now = self._datetime.datetime.now(self._datetime.timezone.utc)
        return {
            "aud": self.configuration("audience"),
            "iss": self.configuration("issuer"),
            "exp": exp,
            **claims,
            "iat": int(now.timestamp()),
        }

    def audit(self, user, action_name, data=None):
        if not self.configuration("audit"):
            return
        self._columns[self.configuration("audit_column_name")].record(user, action_name, data=None)
