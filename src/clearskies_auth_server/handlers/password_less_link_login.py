import inspect
import json
from jwcrypto import jwk, jwt
from clearskies.handlers.exceptions import ClientError, NotFound
from clearskies.column_types import Audit, String, DateTime
from .password_login import PasswordLogin


class PasswordLessLinkLogin(PasswordLogin):
    _configuration_defaults = {
        "user_model_class": "",
        "key_column_name": "",
        "key_expiration_column_name": "",
        "username_column_name": "",
        "key_source": "query_parameters",
        "key_source_key_name": None,
        "jwt_lifetime_seconds": 86400,
        "issuer": "",
        "audience": "",
        "path_to_private_keys": "",
        "path_to_public_keys": "",
        "key_cache_duration": 7200,
        "claims_callable": None,
        "claims_column_names": None,
        "login_check_callables": [],
        "audit": True,
        "audit_column_name": "audit",
        "audit_action_name_successful_login": "login",
        "audit_action_name_failed_login": "failed_login",
        "audit_overrides": {},
        "users": None,
    }

    _required_configurations = [
        "user_model_class",
        "key_column_name",
        "key_expiration_column_name",
        "username_column_name",
        "issuer",
        "audience",
        "path_to_private_keys",
        "path_to_public_keys",
    ]

    def __init__(self, di, secrets, datetime):
        super().__init__(di, secrets, datetime)
        self._columns = None

    def _my_configuration_checks(self, configuration):
        error_prefix = "Invalid configuration for handler " + self.__class__.__name__ + ":"
        self._check_required_configuration(configuration, error_prefix)
        self._check_user_model_class_configuration(configuration, error_prefix)

        user_model_class = configuration.get("user_model_class")
        user_model = self._di.build(user_model_class)
        self._columns = user_model.columns()
        self._check_claims_configuration(configuration, error_prefix)
        self._check_input_error_callable_configuration(configuration, error_prefix)
        self._check_audit_configuration(configuration, error_prefix)
        self._check_login_check_callables(configuration, error_prefix)

        key_source = configuration.get("key_source")
        if key_source and key_source not in ["query_parameters", "json_body"]:
            raise ValueError(
                f"{error_prefix} invalid value for key_source: '{key_source}'.  It must be one of 'query_parameters' or 'json_body'"
            )

        expected_types = {
            "key_column_name": String,
            "key_expiration_column_name": DateTime,
            "username_column_name": String,
        }
        for config_name in ["key_column_name", "key_expiration_column_name", "username_column_name"]:
            column_name = configuration.get(config_name)
            if column_name not in self._columns:
                raise ValueError(
                    f"{error_prefix} the provided {config_name}, '{column_name}', does not exist in the user model '{user_model_class.__name__}'"
                )
            column = self._columns[column_name]
            if not isinstance(column, expected_types[config_name]):
                name = expected_types[config_name].__name__
                raise ValueError(
                    f"{error_prefix} config {config_name} should be a clearskies column of type {name}, but is not."
                )

    def handle(self, input_output):
        login_key = self.get_login_key(input_output)
        if not login_key:
            return self.error(input_output, "Missing login key.", 404)
        if not isinstance(login_key, str):
            return self.error(input_output, "Login key  was not a string.", 404)

        key_column_name = self.configuration("key_column_name")
        users = self.users
        user = users.find(f"{key_column_name}={login_key}")
        if not user.exists:
            return self.error(input_output, "No matching login session found.", 404)
        username_column_name = self.configuration("username_column_name")
        audit_overrides = self.configuration("audit_overrides")
        audit_extra_data_unmapped = {
            "username": user.get(self.configuration("username_column_name")),
            "user_id": user.get(user.id_column_name),
        }
        audit_extra_data = {}
        for key, value in audit_overrides.items():
            audit_extra_data[value] = audit_extra_data_unmapped[key]

        key_expiration_column_name = self.configuration("key_expiration_column_name")
        expiration = user.get(key_expiration_column_name)
        if not expiration.tzinfo:
            expiration.replace(tzinfo=self._datetime.timezone.utc)
        if not expiration:
            self.audit(
                user,
                self.configuration("audit_action_name_failed_login"),
                data={
                    "reason": "Login refused: missing expiration date for login key.",
                    **audit_extra_data,
                },
            )
            return self.error(input_output, "No matching login session found.", 404)
        if expiration < self._datetime.datetime.now(self._datetime.timezone.utc):
            self.audit(
                user,
                self.configuration("audit_action_name_failed_login"),
                data={
                    "reason": "Attempt to login with single-use key failed due to expired key.",
                    **audit_extra_data,
                },
            )
            return self.error(input_output, "No matching login session found.", 404)

        # developer-defined checks
        login_check_callables = self.configuration("login_check_callables")
        if login_check_callables:
            for login_check_callable in login_check_callables:
                response = self._di.call_function(
                    login_check_callable,
                    user=user,
                    input_output=input_output,
                    **input_output.routing_data(),
                    **input_output.context_specifics(),
                )
                if response:
                    self.audit(
                        user,
                        self.configuration("audit_action_name_failed_login"),
                        data={
                            "reason": response,
                            **audit_extra_data,
                        },
                    )
                    return self.error(input_output, "No matching login session found.", 404)

        signing_key = self.get_youngest_private_key(self.configuration("path_to_private_keys"), as_json=False)
        jwt_claims = self.get_jwt_claims(user)
        token = jwt.JWT(header={"alg": "RS256", "typ": "JWT", "kid": signing_key["kid"]}, claims=jwt_claims)
        token.make_signed_token(signing_key)
        self.audit(user, self.configuration("audit_action_name_successful_login"), data=audit_extra_data)
        user.save(
            {
                key_column_name: "",
                key_expiration_column_name: self._datetime.datetime.now(self._datetime.timezone.utc),
            }
        )

        return self.respond_unstructured(
            input_output,
            {
                "token": token.serialize(),
                "expires_at": jwt_claims["exp"],
            },
            200,
        )

    def get_login_key(self, input_output):
        key_source = self.configuration("key_source")
        key_source_key_name = self.configuration("key_source_key_name")
        if not key_source_key_name:
            key_source_key_name = self.configuration("key_column_name")

        if key_source == "query_parameters":
            return input_output.get_query_parameter(key_source_key_name)
        request_data = input_output.json_body()
        return request_data.get(key_source_key_name)
