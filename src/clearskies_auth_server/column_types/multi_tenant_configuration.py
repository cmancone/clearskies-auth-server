from clearskies.column_types import Column
from clearskies.functional import validations


class MultiTenantConfiguration(Column):
    my_configs = [
        "config_model_class",
        "config_model_class_user_id_column_name",
        "authorization_data_user_id_column_name",
        "config_model_class_tenant_id_column_name",
        "authorization_data_tenant_id_column_name",
        "writeable_column_names",
        "readable_column_names",
    ]

    def __init__(self, di):
        super().__init__(di)

    @property
    def is_readable(self):
        return False

    def _check_configuration(self, configuration):
        super()._check_configuration(configuration)
        # pull out the columns from the config model class and the given model class
        # Validate that there are no overlapping writable columns between the config model class and the
        # given model class
        error_prefix = f"Error for column '{self.name}' in model '{self.model_class.__name__}':"
        config_model_class = configuration.get("config_model_class")
        if not config_model_class:
            raise ValueError(f"{error_prefix} you must provide 'config_model_class' when using the multi_tenant_configuration column type")
        if not validations.is_model_class(config_model_class):
            raise ValueError(f"{error_prefix} the provided value for 'config_model_class' must be a clearskies model class, but instead I got: " + config_model_class.__class__.__name__)
        self.columns = self.di.build(self.model_class, cache=True).columns()
        self.config_models = self.di.build(config_model_class)
        self.config_model_columns = self.config_models.columns()
        self._check_column_names(self.configuration, 'writeable_column_names', self.columns, self.config_model_columns, writeable=True)
        self._check_column_names(self.configuration, 'readable_column_names', self.columns, self.config_model_columns, writeable=False)
        self._check_config_model_column_name(configuration, 'config_model_class_user_id_column_name', config_model_class, self.config_model_columns)

    def _check_column_names(configuration, key, model_columns, config_columns, writeable=False):
        config_model_class_name = configuration.get("config_model_class").__name__
        if not configuration.get(key):
            raise ValueError(f"{error_prefix} you must provide '{key}', which should be a list of column names from the config model class")
        column_names = configuration.get(key)
        if not isinstance(column_names, list):
            raise ValueError(f"{error_prefix} '{key}' should be a list of column names, but instead of a list it is a " + column_names.__class__.__name__)
        for (index, column_name) in enumerate(column_names):
            if not isinstance(column_name, str):
                raise ValueError(f"{error_prefix} '{key}' should be a list of column names, but entry #{index+1} is not a string.  Instead, it is a " + column_name.__class__.__name__)
            if column_name not in config_columns:
                from_provides = False
                if not writeable:
                    for model_column in model_columns:
                        if model_column.can_provide(column_name):
                            from_provides = True
                if not from_provides:
                    raise ValueError(f"{error_prefix} '{key}' should be a list of column names from the config model class, '{config_model_class_name}', but entry #{index+1} specifies a column name, '{column_name}' that does not exist in the config model class")
            if column_name in model_columns:
                raise ValueError(f"{error_prefix} entry #{index+1} in '{key}' specifies a column in the config model class, '{column_name}', that already exists in the model class.  This is not allowed.")
            if writeable and not config_columns[column_name].is_writeable:
                raise ValueError(f"{error_prefix} entry #{index+1} in '{key}' specifies a writeable column in the config model class, '{column_name}', but according to the config model class this column is not writeable.")
            if not writeable and not config_columns[column_name].is_readable:
                raise ValueError(f"{error_prefix} entry #{index+1} in '{key}' specifies a readable column in the config model class, '{column_name}', but according to the config model class this column is not readable.")

    def _check_config_model_column_name(configuration, config_name, config_model_class, config_model_columns):
        config_model_column_name = configuration.get(config_name)
        if not config_model_column_name:
            raise ValueError(f"{error_prefix} you must provide '{config_name}' when using the multi_tenant_configuration column type.  It should be the name of a column in the config model class.")
        if not isinstance(config_model_column_name, str):
            raise ValueError(f"{error_prefix} the value specified in '{config_model_column_name}' should be a string, but instead it is a " + config_model_column_name.__class__.__name__)
        if config_model_column_name not in config_model_columns:
            raise ValueError(f"{error_prefix} the column name specified in '{config_name}', '{config_model_column_name}', does not exist in the config model class, '{config_model_class.__name__}'")

    def post_save(self, data, model, id):
        # gather our data, find the config model class, and save.
        # also, remove the column data before returning so the other columns
        # won't trigger their post-saves
        config_model_data = {}
        for column_name in self.config('writeable_column_names'):
            if column_name not in data:
                continue
            config_model_data[column_name] = data[column_name]
            del data[column_name]

        if config_model_data:
            # model.get() returns None if the model doesn't exist, so we have to split up create and update
            # we kinda have to anyway, because with create we need to also provide the user id and tenant id.
            config_model = model.get(self.name) if model.exists else self.config_models.blank()
            if not config_model.exists:
                config_model_data = {
                    **config_model_data,
                    **self._get_record_selector_data(),
                }
            config_model.save(config_model_data)

        return data

    def additional_write_columns(self, is_create=False):
        extra_columns = super().additional_write_columns(is_create=is_create)

        # we need to clone the column and set the `is_temporary` flag to true.  This will ensure that it doesn't try to save data to the database
        # during the normal save flow (which will fail, since we're effectively moving the column to a different model class, which obviously won't
        # have the same columns in th backend.  In our post save, we'll re-direct the data to save it in the right place.
        for column_name in self.config('writeable_column_names'):
            column_to_clone = self.config_model_columns[column_name]
            new_column = self.di.build(column_to_clone.__class__)
            new_column.configure({
                **column_to_clone.configuration,
                "is_temporary": True,
            })
            extra_columns.update(column_name, new_column)

        return extra_columns

    def can_provide(self, column_name):
        return column_name == self.name or column_name in self.configuration("readable_column_names")

    def provide(self, data, column_name):
        if column_name == self.name:
            models = self.config_models
            for (column_name, value) in self._get_record_selector_data():
                models = models.where(f"{column_name}={value}")
            return models.first()

        return self.provide(data, column_name).get(column_name)

    def to_json(self, model):
        json_data = {}
        config_model = model.get(self.name)
        for column_name in self.readable_column_names:
            json_data = {
                **json_data,
                **self.config_model_columns[column_name].to_json(config_model),
            }
        return json_data

    def _get_record_selector_data(self):
        authorization_data = self.di.build('input_output', cache=True)
        user_id_column_name = self.config("config_model_class_user_id_column_name")
        tenant_id_column_name = self.config("config_model_class_tenant_id_column_name")
        user_id = authorization_data.get(self.config("authorization_data_user_id_column_name"))
        tenant_id = authorization_data.get(self.config("authorization_data_tenant_id_column_name"))
        if not user_id:
            raise ValueError("I was asked to fetch the multi tenant config for a given user, but I didn't find any data in the authorization data under " + self.config("authorization_data_user_id_column_name"))
        if not tenant_id:
            raise ValueError("I was asked to fetch the multi tenant config for a given user, but I didn't find any data in the authorization data under " + self.config("authorization_data_tenant_id_column_name"))
        return {
            user_id_column_name: user_id,
            authorization_data_tenant_id_column_name: tenant_id,
        }

    ###########
    ##########
    def input_errors(self, model, data):
        error = self.check_input(model, data)
        if error:
            return {self.name: error}

        for requirement in self.config("input_requirements"):
            error = requirement.check(model, data)
            if error:
                return {self.name: error}

        return {}

    def check_input(self, model, data):
        if self.name not in data or not data[self.name]:
            return ""
        return self.input_error_for_value(data[self.name])
