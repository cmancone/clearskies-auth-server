import unittest
from unittest.mock import MagicMock
from .have_i_been_pwned import HaveIBeenPwned


class HaveIBeenPwnedTest(unittest.TestCase):
    def test_leaked(self):
        response = MagicMock()
        response.content = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:10".encode("utf-8")
        requests = MagicMock()
        requests.get = MagicMock(return_value=response)
        have_i_been_pwned = HaveIBeenPwned(requests)
        have_i_been_pwned.column_name = "password"

        error = have_i_been_pwned.check("model", {"password": "password"})
        self.assertIn("password has been leaked", error)
        requests.get.assert_called_with("https://api.pwnedpasswords.com/range/5BAA6")

    def test_okay(self):
        response = MagicMock()
        response.content = "1E4C9B93F3F0682250B6CF8331B7EE68FD8:10".encode("utf-8")
        requests = MagicMock()
        requests.get = MagicMock(return_value=response)
        have_i_been_pwned = HaveIBeenPwned(requests)
        have_i_been_pwned.column_name = "password"

        error = have_i_been_pwned.check("model", {"password": "asdfibeijereijfeijere"})
        self.assertEquals("", error)
        requests.get.assert_called_with("https://api.pwnedpasswords.com/range/9D3D8")
