from collections import OrderedDict
from clearskies.input_requirements import Requirement, required
from clearskies.column_types import String


class PasswordValidation(Requirement):
    def __init__(self, di):
        self.di = di

    def configure(self, password_column_name="password"):
        self.password_column_name = password_column_name

    def check(self, model, data):
        has_value = False
        has_some_value = False
        # if the column isn't being set at all, then we don't care.
        if self.column_name not in data:
            return ""
        model_columns = model.columns()
        if self.password_column_name not in model_columns:
            raise ValueError(
                f"Whoops, password validation is improperly configured for column {self.column_name} in model {model.__class__.__name__}: the password column name is set to {self.column_name} but this column does not exist in the model"
            )
        if "validate_password" not in data:
            return "You must provide your old password when changing " + self.column_name
        if not model_columns[self.password_column_name].validate_password(model, data.get("validate_password")):
            return "Old password did not match.  You must provide your old password when changing " + self.column_name
        return ""

    def additional_write_columns(self, is_create=False):
        # only needed on update
        if is_create:
            return {}

        column = self.di.build(String, cache=False)
        column.configure("validate_password", {"is_temporary": True}, self.__class__)
        return {"validate_password": column}
