import secrets
import inspect
from clearskies.handlers.exceptions import InputError
from clearskies.handlers import Delete
from clearskies.column_types import Audit


class DeleteNotSelf(Delete):
    _configuration_defaults = {
        "model": None,
        "model_class": None,
        "readable_columns": None,
        "where": [],
        "user_id_key_in_authorization_data": "id",
    }

    def handle(self, input_output):
        model = self.fetch_model(input_output)
        if type(model) == str:
            return self.error(input_output, model, 404)

        authorization_data = input_output.get_authorization_data()
        user_id_key = self.configuration("user_id_key_in_authorization_data")
        if user_id_key not in authorization_data:
            raise ValueError(
                f"Error for DeleteNotSelf: I was supposed to look for the user id in the authorization data under they key '{user_id_key}' but this key doesn't exist in the authorization data.  Instead I have the following keys: '"
                + "','".join(list(authorization_data.keys()))
                + "'"
            )
        if authorization_data.get(user_id_key) == model.get(model.id_column_name):
            return self.error(input_output, "You cannot delete yourself", 400)

        model.delete()
        return self.success(input_output, {})
