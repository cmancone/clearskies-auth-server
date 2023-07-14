import re
from .letters_digits import LettersDigits


class LettersDigitsSpecialCharacters(LettersDigits):
    special_characters = None

    def configure(self, special_characters="!@#$%^&*()<>,.?~`"):
        if type(special_characters) != str:
            raise ValueError(f"special_characters must be a string with the list of special characters to check for.")
        self.special_characters = special_characters

    def check(self, model, data):
        if not data.get(self.column_name):
            return ""
        error = super().check(model, data)
        if error:
            return error
        value = data[self.column_name]
        found = False
        for character in self.special_characters:
            if character not in value:
                continue
            found = True
            break

        if not found:
            return (
                f"{self.column_name} must contain at least one special character from the following list: "
                + ", ".join(list(self.special_characters))
            )
        return ""
