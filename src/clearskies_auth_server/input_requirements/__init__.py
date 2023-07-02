from clearskies.binding_config import BindingConfig
from .letters_digits import LettersDigits
from .letters_digits_special_characters import LettersDigitsSpecialCharacters
def letters_digits():
    return BindingConfig(LettersDigits)
def letters_digits_special_characters(special_characters='!@#$%^&*()<>,.?~`'):
    return BindingConfig(LettersDigitsSpecialCharacters, special_characters=special_characters)
__all__ = [
    "letters_digits",
    "letters_digits_special_characters",
    "LettersDigits",
    "LettersDigitsSpecialCharacters",
]
