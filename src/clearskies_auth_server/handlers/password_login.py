import inspect
import json
from jwcrypto import jwk, jwt
from clearskies.handlers.exceptions import InputError
from clearskies.column_types import Audit
from .key_base import KeyBase
import datetime


class PasswordLogin(KeyBase):
    _configuration_defaults = {
        "user_model_class": "",
        "username_column_name": "email",
        "password_column_name": "password",
        "tenant_id_column_name": None,
        "tenant_id_source": None,
        "tenant_id_source_key_name": None,
        "jwt_lifetime_seconds": 86400,
        "issuer": "",
        "audience": "",
        "path_to_private_keys": "",
        "path_to_public_keys": "",
        "key_cache_duration": 7200,
        "claims_callable": None,
        "claims_column_names": None,
        "input_error_callable": None,
        "login_check_callables": [],
        "audit": True,
        "audit_column_name": "audit",
        "audit_action_name_successful_login": "login",
        "audit_action_name_failed_login": "failed_login",
        "audit_action_name_account_locked": "account_lockout",
        "audit_overrides": {},
        "account_lockout": True,
        "account_lockout_failed_attempts_threshold": 10,
        "account_lockout_failed_attempts_period_minutes": 5,
        "users": None,
    }

    _required_configurations = [
        "issuer",
        "audience",
        "user_model_class",
        "path_to_private_keys",
        "path_to_public_keys",
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

        if configuration.get("account_lockout") and not configuration.get("audit"):
            raise ValueError(
                f"{error_prefix} 'account_lockout' is set to True but 'audit' is False.  You must enable auditing to turn on account lockouts."
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
            if configuration.get("audit_overrides"):
                overrides = configuration.get("audit_overrides")
                if not isinstance(overrides, dict):
                    raise ValueError(
                        f"{error_prefix} 'audit_overrides' must be a dictionary to map where user data goes in the audit record."
                    )
                unexpected = set(overrides.keys()) - set(["username", "tenant_id", "user_id"])
                if unexpected:
                    raise ValueError(
                        f"{error_prefix} received unexpected keys for 'audit_overrides'.  Allowed keys are 'username', 'tenant_id', and 'user_id', but I found "
                        + ", ".join(unexpected)
                    )

        if configuration.get("login_check_callables"):
            login_check_callables = configuration.get("login_check_callables")
            if not isinstance(login_check_callables, list):
                raise ValueError(
                    f"{error_prefix} 'login_check_callables' should be a list, but instead it has type '"
                    + type(login_check_callables)
                    + "'"
                )
            for index, login_check_callable in enumerate(login_check_callables):
                if not callable(login_check_callable):
                    raise ValueError(
                        f"{error_prefix} each entry in 'login_check_callables' should be a callable, but entry #{index} is not callable."
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

    def handle(self, input_output):
        request_data = self.request_data(input_output)
        input_errors = self._find_input_errors(self.users, request_data, input_output)
        if input_errors:
            raise InputError(input_errors)

        username_column_name = self.configuration("username_column_name")
        password_column_name = self.configuration("password_column_name")
        password_column = self._columns[password_column_name]
        tenant_id_value = None
        users = self.users
        if self.configuration("tenant_id_column_name"):
            tenant_id_column_name = self.configuration("tenant_id_column_name")
            tenant_id_source_key_name = self.configuration("tenant_id_source_key_name")
            if self.configuration("tenant_id_source") == "routing_data":
                tenant_id_value = input_output.routing_data().get(tenant_id_source_key_name)
            if not tenant_id_value:
                return self.input_errors(input_output, {username_column_name: "Invalid username/password combination"})
            users = users.where(f"{tenant_id_column_name}={tenant_id_value}")
        username = request_data[username_column_name]
        user = users.find(f"{username_column_name}={username}")
        audit_overrides = self.configuration("audit_overrides")
        audit_extra_data_unmapped = {
            "username": username,
            "user_id": user.get(user.id_column_name),
            "tenant_id": tenant_id_value,
        }
        audit_extra_data = {}
        for key, value in audit_overrides.items():
            audit_extra_data[value] = audit_extra_data_unmapped[key]

        # no user found
        if not user.exists:
            return self.input_errors(input_output, {username_column_name: "Invalid username/password combination"})

        # account lockout
        if self.account_locked(user):
            self.audit(
                user,
                self.configuration("audit_action_name_account_locked"),
                data={
                    "reason": "Account Locked",
                    **audit_extra_data,
                },
            )
            minutes = self.configuration("account_lockout_failed_attempts_threshold")
            s = "s" if int(minutes) != 1 else ""
            return self.input_errors(
                input_output,
                {
                    username_column_name: f"Your account is under a {minutes}{s} minute lockout due to too many failed login attempts"
                },
            )

        # password not set
        if not user.get(password_column_name):
            self.audit(
                user,
                self.configuration("audit_action_name_failed_login"),
                data={
                    "reason": "Password not set - user is not configured for password login",
                    **audit_extra_data,
                },
            )
            return self.input_errors(input_output, {username_column_name: "Invalid username/password combination"})

        # invalid password
        if not password_column.validate_password(user, request_data[password_column_name]):
            self.audit(
                user,
                self.configuration("audit_action_name_failed_login"),
                data={
                    "reason": "Invalid password",
                    **audit_extra_data,
                },
            )
            return self.input_errors(input_output, {username_column_name: "Invalid username/password combination"})

        # developer-defined checks
        login_check_callables = self.configuration("login_check_callables")
        if login_check_callables:
            for login_check_callable in login_check_callables:
                response = self._di.call_function(
                    login_check_callable,
                    user=user,
                    request_data=request_data,
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
                    return self.input_errors(input_output, {username_column_name: response})

        self.audit(user, self.configuration("audit_action_name_successful_login"), data=audit_extra_data)
        signing_key = self.get_youngest_private_key(self.configuration("path_to_private_keys"), as_json=False)
        jwt_claims = self.get_jwt_claims(user)
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

    def account_locked(self, user):
        if not self.configuration("account_lockout"):
            return True

        threshold_time = datetime.datetime.now() - datetime.timedelta(
            minutes=self.configuration("account_lockout_failed_attempts_period_minutes")
        )
        audit_column_name = self.configuration("audit_column_name")
        failed_attempts = user.get(audit_column_name).where(
            "action=" + self.configuration("audit_action_name_failed_login")
        )
        failed_attempts = failed_attempts.where("created_at>" + threshold_time.strftime("%Y-%m-%d %H:%M:%S"))
        return len(failed_attempts) >= self.configuration("account_lockout_failed_attempts_threshold")

    def request_data(self, input_output, required=True):
        # make sure we don't drop any data along the way, because the input validation
        # needs to return an error for unexpected data.
        column_map = {
            self.configuration("username_column_name"): self.auto_case_column_name(
                self.configuration("username_column_name"), True
            ),
            self.configuration("password_column_name"): self.auto_case_column_name(
                self.configuration("password_column_name"), True
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
            self.configuration("password_column_name"),
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

    def get_jwt_claims(self, user):
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
            "exp": int((now + datetime.timedelta(seconds=self.configuration("jwt_lifetime_seconds"))).timestamp()),
            **claims,
            "iat": int(now.timestamp()),
        }

    def audit(self, user, action_name, data=None):
        if not self.configuration("audit"):
            return
        self._columns[self.configuration("audit_column_name")].record(user, action_name, data=data)
