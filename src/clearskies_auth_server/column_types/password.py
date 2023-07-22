from clearskies.column_types import String
from clearskies.input_requirements import required
from passlib.context import CryptContext


class Password(String):
    _crypt_context = None

    my_configs = [
        "crypt_context",
        "crypt_context_string",
        "crypt_context_path",
        "require_repeat_password",
        "repeat_password_column_name",
        "for_login",
    ]

    crypt_config_names = [
        "crypt_context",
        "crypt_context_string",
        "crypt_context_path",
    ]

    def __init__(self, di):
        super().__init__(di)

    @property
    def is_readable(self):
        return False

    def _check_configuration(self, configuration):
        super()._check_configuration(configuration)
        count = 0
        for config_name in self.crypt_config_names:
            if configuration.get(config_name):
                count += 1
        if count > 1:
            raise ValueError(
                f"Error for column '{self.name}' in model '{self.model_class.__name__}': "
                + "you can only provide one of 'crypt_context', 'crypt_context_string', and 'crypt_context_path', "
                + "but more than one was found"
            )
        repeat_password_column_name = configuration.get("repeat_password_column_name", "repeat_password")
        if not isinstance(repeat_password_column_name, str):
            raise ValueError(
                f"Error for column '{self.name}' in model '{self.model_class.__name__}': "
                + "repeat_password_column_name should be a string, but instead I received a "
                + str(type(repeat_password_column_name))
            )

    def _finalize_configuration(self, configuration):
        configuration = super()._finalize_configuration(
            {
                "require_repeat_password": True,
                "repeat_password_column_name": "repeat_password",
                "for_login": False,
                **configuration,
            }
        )
        found = False
        for config_name in self.crypt_config_names:
            if config_name in configuration:
                found = True
                break
        if not found:
            configuration["crypt_context"] = {
                "schemes": ["argon2"],
                "argon2__rounds": 5,
            }
        return configuration

    def configure(self, name, configuration, model_class):
        super().configure(name, configuration, model_class)
        if "crypt_context" in self.configuration:
            self._crypt_context = CryptContext(**self.config("crypt_context"))
        elif "crypt_context_string" in self.configuration:
            self._crypt_context = CryptContext.from_string(self.config("crypt_context_string"))
        else:
            self._crypt_context = CryptContext.from_path(self.config("crypt_context_path"))

    def check_input(self, model, data):
        if self.name not in data or not data[self.name]:
            return ""
        # if we're providing a password, then it must match the value in 'repeat_password'
        if self.config("for_login"):
            return ""
        repeat_password = data.get("repeat_password")
        password = data.get("password")
        return "Passwords did not match" if password != repeat_password else ""

    def pre_save(self, data, model):
        # if the password is being set to a non-value, then unset it
        if self.name in data and not data[self.name]:
            del data[self.name]
        elif data.get(self.name):
            data[self.name] = self._crypt_context.hash(data[self.name])
        if self.config("require_repeat_password") and not self.config("for_login") and "repeat_password" in data:
            del data["repeat_password"]
        return data

    def validate_password(self, user, password):
        hashed_password = user.get(self.name)
        if not hashed_password:
            return False

        if not self._crypt_context.verify(password, hashed_password):
            return False

        # yes, I understand that the crypt context has a `verify_and_update` flow for this, but
        # re-organizing the code to support that isn't worth the relatively minor efficiency gains.
        # The save process will automatically hash the password, so there isn't a flow to pass in
        # an already-hashed password.
        if self._crypt_context.needs_update(hashed_password):
            user.save({self.name: password})
        return True

    def additional_write_columns(self, is_create=False):
        if self.config("for_login"):
            return {}

        extra_columns = super().additional_write_columns(is_create=is_create)
        if self.config("require_repeat_password"):
            repeat_password_column = self.di.build(String, cache=False)
            repeat_password_column.configure("repeat_password", {"is_temporary": True}, self.model_class)
            extra_columns["repeat_password"] = repeat_password_column
        return extra_columns
