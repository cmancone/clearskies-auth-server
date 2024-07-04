import clearskies


class Me(clearskies.di.AdditionalConfig):
    def __init__(
        self,
        user_model_class=None,
        user_id_key_in_authorization_data="user_id",
        user_di_name="my_user",
        tenant_model_class=None,
        tenant_id_key_in_authorization_data="tenant_id",
        tenant_di_name="my_tenant",
    ):
        self.user_model_class = user_model_class
        self.user_id_key_in_authorization_data = user_id_key_in_authorization_data
        self.user_di_name = user_di_name
        self.tenant_model_class = tenant_model_class
        self.tenant_id_key_in_authorization_data = tenant_id_key_in_authorization_data
        self.tenant_di_name = tenant_di_name

    def can_cache(self, name, context=None):
        return False

    def can_build(self, name):
        return name in [self.user_di_name, self.tenant_di_name]

    def build(self, name, di, context=None):
        if name == self.user_di_name:
            model_class = self.user_model_class
            id_key_in_authorization_data = self.user_id_key_in_authorization_data
        else:
            model_class = self.tenant_model_class
            id_key_in_authorization_data = self.tenant_id_key_in_authorization_data

        error_prefix = f"{name} was requested from the 'Me' provider of the auth server"
        if not model_class:
            raise ValueError(
                f"{error_prefix}, but I can't provide it because I wasn't given the corresponding model class"
            )

        models = di.build(model_class)
        input_output = di.build("input_output", cache=True)
        authorization_data = input_output.get_authorization_data()
        id = authorization_data.get(id_key_in_authorization_data)
        if not id:
            raise ValueError(
                f"{error_prefix}, but the corresponding key in the authorization data, '{id_key_in_authorization_data}' does not exist or is empty.  Perhaps you forgot to set an authentication rule on your endpoint?"
            )

        id_column_name = models.id_column_name
        model = models.find(f"{id_column_name}={id}")
        if not model.exists:
            raise ValueError(
                f"{error_prefix}, but when I searched for {id_column_name}={id} in the class {model_class.__name__} I didn't find anything"
            )

        return model
