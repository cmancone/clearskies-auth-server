import clearskies


class Profile(clearskies.handlers.Update):
    def __init__(self, di):
        super().__init__(di)

    _configuration_defaults = {
        "user_id_key_in_authorization_data": None,
        "model": None,
        "model_class": None,
        "columns": None,
        "writeable_columns": None,
        "readable_columns": None,
        "where": [],
        "input_error_callable": None,
        "include_id_in_path": False,
    }

    def get_model_id(self, input_output, input_data):
        authorization_data = input_output.get_authorization_data()
        return authorization_data.get(self.configuration("user_id_key_in_authorization_data"))

    def _check_configuration(self, configuration):
        super()._check_configuration(configuration)
        error_prefix = "Configuration error for %s:" % (self.__class__.__name__)
        if not configuration.get("user_id_key_in_authorization_data"):
            raise ValueError(
                f"{error_prefix} missing required configuration setting, 'user_id_key_in_authorization_data'. "
                + "This should be the name of the key in the authorization data where the user id is stored."
            )

    def documentation(self):
        return self._documentation(
            description="Modify the user's profile",
            response_description=f"The updated profile",
            include_id_in_path=False,
        )
