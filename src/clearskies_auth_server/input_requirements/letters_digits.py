import re
from clearskies.input_requirements.requirement import Requirement


class LettersDigits(Requirement):
    def configure(self):
        pass

    def check(self, model, data):
        if not data.get(self.column_name):
            return ""
        if not re.search("\d", data[self.column_name]):
            return f"{self.column_name} must contain numbers and letters, but does not contain any numbers."
        if not re.search("[a-zA-Z]", data[self.column_name]):
            return f"{self.column_name} must contain numbers and letters, but does not contain any letters."
        return ""
