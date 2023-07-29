from clearskies.binding_config import BindingConfig
from .letters_digits import LettersDigits
from .letters_digits_special_characters import LettersDigitsSpecialCharacters
from .password_validation import PasswordValidation


def letters_digits():
    return BindingConfig(LettersDigits)


def letters_digits_special_characters(special_characters="!@#$%^&*()<>,.?~`"):
    return BindingConfig(LettersDigitsSpecialCharacters, special_characters=special_characters)


def password_validation(password_column_name):
    return BindingConfig(PasswordValidation, password_column_name=password_column_name)


__all__ = [
    "letters_digits",
    "letters_digits_special_characters",
    "LettersDigits",
    "LettersDigitsSpecialCharacters",
    "password_validation",
    "PasswordValidation",
]
