import datetime as datetime_module
from jose import jwt
from collections import OrderedDict
import unittest
from unittest.mock import MagicMock, call
from .key_base_test import KeyBaseTest
from .password_less_link_login import PasswordLessLinkLogin
import clearskies
from clearskies.contexts import test
from clearskies.column_types import audit, email, json, string, datetime, created, updated


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
                email("email"),
                string("login_code"),
                datetime("login_code_expiration"),
                audit("audit", audit_models_class=AuditRecord),
            ]
        )


class PasswordLessLinkLoginTest(KeyBaseTest):
    def setUp(self):
        super().setUp()

        self.login = test(
            {
                "handler_class": PasswordLessLinkLogin,
                "handler_config": {
                    "claims_column_names": ["email"],
                    "path_to_private_keys": "/path/to/private",
                    "path_to_public_keys": "/path/to/public",
                    "user_model_class": User,
                    "issuer": "https://example.com",
                    "audience": "example.com",
                    "key_column_name": "login_code",
                    "username_column_name": "email",
                    "key_expiration_column_name": "login_code_expiration",
                },
            },
            bindings={"secrets": self.secrets},
            binding_classes=[User, AuditRecord],
        )

        self.users = self.login.build("users")
        self.user = self.users.create(
            {
                "email": "cmancone@example.com",
                "login_code": "asdfer",
                "login_code_expiration": datetime_module.datetime.utcnow() + datetime_module.timedelta(hours=5),
            }
        )

    def never(self):
        return "not gonna happen"

    def always(self):
        return ""

    def test_success(self):
        (response, status_code) = self.login(
            query_parameters={
                "login_code": "asdfer",
            }
        )
        raw_jwt = response["token"]
        jwt_claims = jwt.decode(
            raw_jwt,
            self.public_keys[self.key_id],
            algorithms=["RS256"],
            audience="example.com",
            issuer="https://example.com",
        )
        self.assertEquals(200, status_code)
        self.assertEquals("cmancone@example.com", jwt_claims["email"])
        self.assertEquals(["create", "login", "update"], [audit.action for audit in self.user.audit])

    def test_failure_no_match(self):
        (response, status_code) = self.login(
            query_parameters={
                "login_code": "asdferer",
            }
        )
        self.assertEquals(404, status_code)
        self.assertEquals("client_error", response["status"])
        self.assertEquals("No matching login session found.", response["error"])

    def test_failure_no_input(self):
        (response, status_code) = self.login()
        self.assertEquals(404, status_code)
        self.assertEquals("client_error", response["status"])
        self.assertEquals("Missing login key.", response["error"])

    def test_failure_expired(self):
        self.user.save({"login_code_expiration": datetime_module.datetime.now()})
        (response, status_code) = self.login(
            query_parameters={
                "login_code": "asdfer",
            }
        )
        self.assertEquals(404, status_code)
        self.assertEquals("client_error", response["status"])
        self.assertEquals("No matching login session found.", response["error"])
        self.assertEquals(["create", "update", "failed_login"], [audit.action for audit in self.user.audit])

    def test_login_check_true(self):
        login = test(
            {
                "handler_class": PasswordLessLinkLogin,
                "handler_config": {
                    "claims_column_names": ["email"],
                    "path_to_private_keys": "/path/to/private",
                    "path_to_public_keys": "/path/to/public",
                    "user_model_class": User,
                    "issuer": "https://example.com",
                    "audience": "example.com",
                    "key_column_name": "login_code",
                    "username_column_name": "email",
                    "key_expiration_column_name": "login_code_expiration",
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
                "login_code": "asdfer",
                "login_code_expiration": datetime_module.datetime.utcnow() + datetime_module.timedelta(hours=5),
            }
        )
        response = login(
            query_parameters={
                "login_code": "asdfer",
            }
        )
        self.assertEquals(200, response[1])

    def test_login_check_false(self):
        login = test(
            {
                "handler_class": PasswordLessLinkLogin,
                "handler_config": {
                    "claims_column_names": ["email"],
                    "path_to_private_keys": "/path/to/private",
                    "path_to_public_keys": "/path/to/public",
                    "user_model_class": User,
                    "issuer": "https://example.com",
                    "audience": "example.com",
                    "key_column_name": "login_code",
                    "username_column_name": "email",
                    "key_expiration_column_name": "login_code_expiration",
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
                "login_code": "asdfer",
                "login_code_expiration": datetime_module.datetime.utcnow() + datetime_module.timedelta(hours=5),
            }
        )
        response = login(
            query_parameters={
                "login_code": "asdfer",
            }
        )
        self.assertEquals(404, response[1])
