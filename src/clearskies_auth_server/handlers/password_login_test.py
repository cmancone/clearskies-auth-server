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
        return OrderedDict([
            string("class"),
            string("resource_id"),
            string("action"),
            json("data"),
            created("created_at"),
            updated("updated_at"),
        ])
class User(clearskies.Model):
    def __init__(self, memory_backend, columns):
        super().__init__(memory_backend, columns)

    def columns_configuration(self):
        return OrderedDict([
            email("email", input_requirements=[required()]),
            password("password", input_requirements=[required()]),
            audit("audit", audit_models_class=AuditRecord),
        ])
class PasswordLoginTest(KeyBaseTest):
    def test_success(self):
        login = test(
            {
                'handler_class': PasswordLogin,
                'handler_config': {
                    'path_to_private_keys': '/path/to/private',
                    'path_to_public_keys': '/path/to/public',
                    'user_model_class': User,
                    'issuer': 'example.com',
                    'audience': 'example.com',
                },
            },
            bindings={'secrets': self.secrets},
            binding_classes=[User, AuditRecord],
        )

        users = login.build("users")
        users.create({
            'email': 'cmancone@example.com',
            'password': 'crappypassword',
        })

        login(body={
            'email': 'cmancone@example.com',
            'password': 'crappypassword',
        })
