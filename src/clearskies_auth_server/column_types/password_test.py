import unittest
from unittest.mock import MagicMock
from .password import Password
import datetime
from passlib.context import CryptContext
class PasswordTest(unittest.TestCase):
    def setUp(self):
        self.default_crypt_context = CryptContext(
            schemes=["argon2"],
            argon2__rounds=5,
        )

        self.user = MagicMock()
        self.user.exists = False

    def test_pre_save_defaults(self):
        password = Password("di")
        password.configure("password", {}, self.user)
        data = password.pre_save({"password": "notastrongpassword"}, self.user)
        self.assertTrue(self.default_crypt_context.verify("notastrongpassword", data["password"]))

    def test_pre_save_nothing(self):
        password = Password("di")
        password.configure("password", {}, self.user)
        data = password.pre_save({"password": ""}, self.user)
        self.assertTrue("password" not in data)

    def test_validate(self):
        password = Password("di")
        password.configure("password", {}, self.user)
        hashed = self.default_crypt_context.hash("notastrongpassword")

        self.user.get = MagicMock(return_value=hashed)
        self.assertTrue(password.validate_password(self.user, "notastrongpassword"))

    def test_validate_and_upgrade(self):
        password = Password("di")
        password.configure(
            "password", {
                "crypt_context": {
                    "schemes": ["argon2", "sha256_crypt"],
                    "deprecated": ["sha256_crypt"],
                },
            }, self.user
        )
        sha256 = CryptContext(schemes=["sha256_crypt"])
        hashed = sha256.hash("notastrongpassword")

        self.user.get = MagicMock(return_value=hashed)
        self.user.save = MagicMock()
        self.assertTrue(password.validate_password(self.user, "notastrongpassword"))
        self.user.save.assert_called_with({"password": "notastrongpassword"})
