from clearskies.column_types import BelongsTo


class TenantId(BelongsTo):
    required_configs = [
        "parent_models_class",
        "source",
        "source_key_name",
    ]

    my_configs = [
        "model_column_name",
        "readable_parent_columns",
        "join_type",
    ]

    def __init__(self, di):
        super().__init__(di)

    @property
    def is_writeable(self):
        return False

    def _check_configuration(self, configuration):
        super()._check_configuration(configuration)
        error_prefix = f"Error for column '{self.name}' in model '{self.model_class.__name__}':"
        if configuration.get("source") not in ["authorization_data", "routing_data"]:
            raise ValueError(
                f"{error_prefix} 'source' must be either 'authorization_data' or 'routing_data', but was something else."
            )

    def _get_tenant_id(self):
        input_output = self.di.build("input_output", cache=True)
        source = self.config("source")
        source_key_name = self.config("source_key_name")
        data = input_output.get_authorization_data() if source == "authorization_data" else input_output.routing_data()
        tenant_id = data.get(source_key_name)
        if not tenant_id:
            raise ValueError(f"I couldn't find the tenant id in the {source} under the key {source_key_name}")
        return tenant_id

    def pre_save(self, data, model):
        # we need to provide the tenant id during a create operation
        if not model.exists:
            data[self.name] = self._get_tenant_id()
        return data

    def where_for_request(self, models, routing_data, authorization_data, input_output):
        """
        A hook to automatically apply filtering whenever the column makes an appearance in a get/update/list/search handler.
        """
        return models.where(f"{self.name}=" + self._get_tenant_id())
