import unittest
from unittest.mock import MagicMock
from .letters_digits_special_characters import LettersDigitsSpecialCharacters


class LettersDigitsSpecialCharactersTest(unittest.TestCase):
    def setUp(self):
        self.letters_digits_special_characters = LettersDigitsSpecialCharacters()
        self.letters_digits_special_characters.column_name = "password"
        self.letters_digits_special_characters.configure(special_characters=":!")

    def test_check(self):
        error = self.letters_digits_special_characters.check("model", {"password": "asdf1234!"})
        self.assertEquals("", error)
        error = self.letters_digits_special_characters.check("model", {"password": ""})
        self.assertEquals("", error)
        error = self.letters_digits_special_characters.check("model", {})
        self.assertEquals("", error)
        error = self.letters_digits_special_characters.check("model", {"password": "asdfer!"})
        self.assertEquals("password must contain numbers and letters, but does not contain any numbers.", error)
        error = self.letters_digits_special_characters.check("model", {"password": "12345!"})
        self.assertEquals("password must contain numbers and letters, but does not contain any letters.", error)
        error = self.letters_digits_special_characters.check("model", {"password": "asdf12345"})
        self.assertEquals("password must contain at least one special character from the following list: :, !", error)
