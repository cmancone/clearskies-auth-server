import datetime
from jose import jwt
from collections import OrderedDict
import unittest
from unittest.mock import MagicMock, call
from types import SimpleNamespace
from jwcrypto import jwk
from .key_base_test import KeyBaseTest
from .password_login import PasswordLogin
import clearskies
from clearskies.contexts import test
from clearskies.column_types import audit, email, json, string, created, updated
from clearskies.input_requirements import required
from ..column_types import password


class AuditRecord(clearskies.Model):
    def __init__(self, memory_backend, columns):
        super().__init__(memory_backend, columns)

    def columns_configuration(self):
        return OrderedDict(
            [
                string("class"),
                string("resource_id"),
                string("action"),
                json("data"),
                created("created_at"),
                updated("updated_at"),
            ]
        )


class User(clearskies.Model):
    def __init__(self, memory_backend, columns):
        super().__init__(memory_backend, columns)

    def columns_configuration(self):
        return OrderedDict(
            [
                email("email", input_requirements=[required()]),
                password("password", input_requirements=[required()]),
                audit("audit", audit_models_class=AuditRecord),
            ]
        )


class PasswordLoginTest(KeyBaseTest):
    def setUp(self):
        super().setUp()
        self.login = test(
            {
                "handler_class": PasswordLogin,
                "handler_config": {
                    "claims_column_names": ["email"],
                    "path_to_private_keys": "/path/to/private",
                    "path_to_public_keys": "/path/to/public",
                    "user_model_class": User,
                    "issuer": "https://example.com",
                    "audience": "example.com",
                    "audit_overrides": {
                        "username": "email",
                        "user_id": "user_id",
                    },
                },
            },
            bindings={"secrets": self.secrets},
            binding_classes=[User, AuditRecord],
        )

        self.users = self.login.build("users")
        self.user = self.users.create(
            {
                "email": "cmancone@example.com",
                "password": "crappypassword",
            }
        )

    def never(self):
        return "not gonna happen"

    def always(self):
        return ""

    def test_success(self):
        response = self.login(
            body={
                "email": "cmancone@example.com",
                "password": "crappypassword",
            }
        )
        raw_jwt = response[0]["token"]
        jwt_claims = jwt.decode(
            raw_jwt,
            self.public_keys[self.key_id],
            algorithms=["RS256"],
            audience="example.com",
            issuer="https://example.com",
        )
        self.assertEquals(200, response[1])
        self.assertEquals("cmancone@example.com", jwt_claims["email"])
        self.assertEquals(["create", "login"], [audit.action for audit in self.user.audit])

    def test_failure_non_user(self):
        response = self.login(
            body={
                "email": "cman@example.com",
                "password": "crappypassword",
            }
        )
        self.assertEquals(404, response[1])
        self.assertEquals("client_error", response[0]["status"])
        self.assertEquals([], response[0]["data"])
        self.assertEquals(["create"], [audit.action for audit in self.user.audit])

    def test_failure_wrong_password(self):
        response = self.login(
            body={
                "email": "cmancone@example.com",
                "password": "wrongpassword",
            }
        )
        self.assertEquals(404, response[1])
        self.assertEquals("client_error", response[0]["status"])
        self.assertEquals([], response[0]["data"])
        self.assertEquals(["create", "failed_login"], [audit.action for audit in self.user.audit])

    def test_failure_lockout(self):
        response = self.login(
            body={
                "email": "cmancone@example.com",
                "password": "wrongpassword1",
            }
        )
        response = self.login(
            body={
                "email": "cmancone@example.com",
                "password": "wrongpassword2",
            }
        )
        response = self.login(
            body={
                "email": "cmancone@example.com",
                "password": "wrongpassword3",
            }
        )
        response = self.login(
            body={
                "email": "cmancone@example.com",
                "password": "wrongpassword4",
            }
        )
        response = self.login(
            body={
                "email": "cmancone@example.com",
                "password": "wrongpassword5",
            }
        )
        response = self.login(
            body={
                "email": "cmancone@example.com",
                "password": "wrongpassword6",
            }
        )
        response = self.login(
            body={
                "email": "cmancone@example.com",
                "password": "wrongpassword7",
            }
        )
        response = self.login(
            body={
                "email": "cmancone@example.com",
                "password": "wrongpassword8",
            }
        )
        response = self.login(
            body={
                "email": "cmancone@example.com",
                "password": "wrongpassword9",
            }
        )
        response = self.login(
            body={
                "email": "cmancone@example.com",
                "password": "wrongpassword0",
            }
        )
        response = self.login(
            body={
                "email": "cmancone@example.com",
                "password": "wrongpassword1",
            }
        )
        self.assertIn("lockout", response[0]["error"])
        self.assertEquals(404, response[1])
        self.assertEquals("client_error", response[0]["status"])
        self.assertEquals([], response[0]["data"])
        self.assertEquals(
            [
                "create",
                "failed_login",
                "failed_login",
                "failed_login",
                "failed_login",
                "failed_login",
                "failed_login",
                "failed_login",
                "failed_login",
                "failed_login",
                "failed_login",
                "account_lockout",
            ],
            [audit.action for audit in self.user.audit],
        )

    def test_login_check_true(self):
        login = test(
            {
                "handler_class": PasswordLogin,
                "handler_config": {
                    "claims_column_names": ["email"],
                    "path_to_private_keys": "/path/to/private",
                    "path_to_public_keys": "/path/to/public",
                    "user_model_class": User,
                    "issuer": "https://example.com",
                    "audience": "example.com",
                    "login_check_callables": [self.always],
                },
            },
            bindings={"secrets": self.secrets},
            binding_classes=[User, AuditRecord],
        )

        users = login.build("users")
        user = users.create(
            {
                "email": "cmancone@example.com",
                "password": "crappypassword",
            }
        )
        response = login(
            body={
                "email": "cmancone@example.com",
                "password": "crappypassword",
            }
        )
        self.assertEquals(200, response[1])

    def test_login_check_false(self):
        login = test(
            {
                "handler_class": PasswordLogin,
                "handler_config": {
                    "claims_column_names": ["email"],
                    "path_to_private_keys": "/path/to/private",
                    "path_to_public_keys": "/path/to/public",
                    "user_model_class": User,
                    "issuer": "https://example.com",
                    "audience": "example.com",
                    "login_check_callables": [self.never],
                },
            },
            bindings={"secrets": self.secrets},
            binding_classes=[User, AuditRecord],
        )

        users = login.build("users")
        user = users.create(
            {
                "email": "cmancone@example.com",
                "password": "crappypassword",
            }
        )
        response = login(
            body={
                "email": "cmancone@example.com",
                "password": "crappypassword",
            }
        )
        self.assertEquals(404, response[1])
        self.assertEquals("not gonna happen", response[0]["error"])
