from clearskies.column_types.string import String
from passlib.context import CryptContext
class Password(String):
    _crypt_context = None

    my_configs = [
        "crypt_context",
        "crypt_context_string",
        "crypt_context_path",
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
                f"Error for column '{self.name}' in model '{self.model_class.__name__}': " +
                "you can only provide one of 'crypt_context', 'crypt_context_string', and 'crypt_context_path', " +
                "but more than one was found"
            )

    def _finalize_configuration(self, configuration):
        configuration = super()._finalize_configuration(configuration)
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

    def pre_save(self, data, model):
        # if the password is being set to a non-value, then unset it
        if self.name in data and not data[self.name]:
            del data[self.name]
        elif data.get(self.name):
            data[self.name] = self._crypt_context.hash(data[self.name])
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
