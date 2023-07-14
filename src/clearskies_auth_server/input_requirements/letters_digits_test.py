import unittest
from unittest.mock import MagicMock
from .letters_digits import LettersDigits


class LettersDigitsTest(unittest.TestCase):
    def setUp(self):
        self.letters_and_digits = LettersDigits()
        self.letters_and_digits.column_name = "password"

    def test_check(self):
        error = self.letters_and_digits.check("model", {"password": "asdf1234"})
        self.assertEquals("", error)
        error = self.letters_and_digits.check("model", {"password": ""})
        self.assertEquals("", error)
        error = self.letters_and_digits.check("model", {})
        self.assertEquals("", error)
        error = self.letters_and_digits.check("model", {"password": "asdfer"})
        self.assertEquals("password must contain numbers and letters, but does not contain any numbers.", error)
        error = self.letters_and_digits.check("model", {"password": "12345"})
        self.assertEquals("password must contain numbers and letters, but does not contain any letters.", error)
