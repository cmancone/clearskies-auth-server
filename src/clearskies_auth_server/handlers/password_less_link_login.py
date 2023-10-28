import inspect
import json
from jwcrypto import jwk, jwt
from clearskies.handlers.exceptions import InputError
from clearskies.column_types import Audit
from .password_login import PasswordLogin
import datetime


class PasswordLessLinkLogin(PasswordLogin):
    _configuration_defaults = {
        "user_model_class": "",
        "key_column_name": "",
        "key_source": None,
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
        "audit_action_name_account_locked": "account_lockout",
        "audit_overrides": {},
        "users": None,
    }

    _required_configurations = [
        "user_model_class",
        "key_column_name",
        "key_source",
        "key_source_key_name",
        "issuer",
        "audience",
        "path_to_private_keys",
        "path_to_public_keys",
    ]

    def __init__(self, di, secrets, datetime):
        super().__init__(di, secrets, datetime)
        self._columns = None

    def _check_configuration(self, configuration):
        super()._check_configuration(configuration)
        error_prefix = "Invalid configuration for handler " + self.__class__.__name__ + ":"
        self._check_required_configuration(configuration, error_prefix)
        self._check_user_model_class_configuration(configuration, error_prefix)

        user_model = self._di.build(user_model_class)
        self._columns = user_model.columns()
        self._check_claims_configuration(configuration, error_prefix)
        self._check_input_error_callable_configuration(configuration, error_prefix)
        self._check_audit_configuration(configuration, error_prefix)
        self._check_login_check_callables(configuration, error_prefix)

        key_column_name = configuration["key_column_name"]
        if key_column_name not in self._columns:
            raise ValueError(
                f"{error_prefix} the provided username column, '{key_column_name}', does not exist in the user model '{user_model_class.__name__}'"
            )

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
