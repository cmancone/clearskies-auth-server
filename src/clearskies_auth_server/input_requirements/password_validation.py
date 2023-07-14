from collections import OrderedDict
from clearskies.input_requirements import Requirement, required
from clearskies.column_types import string


class PasswordValidation(Requirement):
    def check(self, model, data):
        has_value = False
        has_some_value = False
        if self.column_name in data:
            has_some_value = True
            if type(data[self.column_name]) == str:
                has_value = bool(data[self.column_name].strip())
            else:
                has_value = bool(data[self.column_name])
        if has_value:
            return ""
        if model.exists and model[self.column_name] and not has_some_value:
            return ""
        return f"'{self.column_name}' is required."

    def additional_write_columns(self, is_create=False):
        # only needed on update
        if is_create:
            return {}

        return OrderedDict([string("validate_password", is_temporary=True)])
