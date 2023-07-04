import datetime
from collections import OrderedDict
import unittest
from unittest.mock import MagicMock, call
from .password_reset_request import PasswordResetRequest
import clearskies
from clearskies.contexts import test
from clearskies.column_types import audit, email, json, string, created, updated
from clearskies.column_types import datetime as datetime_column
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
            string("reset_key"),
            datetime_column("reset_key_expiration"),
            audit("audit", audit_models_class=AuditRecord),
        ])
class PasswordResetRequestTest(unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.login = test(
            {
                'handler_class': PasswordResetRequest,
                'handler_config': {
                    'user_model_class': User,
                },
            },
            binding_classes=[User, AuditRecord],
        )

        self.users = self.login.build("users")
        self.user = self.users.create({
            'email': 'cmancone@example.com',
            'password': 'crappypassword',
        })

    def test_success(self):
        response = self.login(body={
            'email': 'cmancone@example.com',
        })
        self.assertEquals({}, response[0]['data'])
        self.assertEquals(200, response[1])

        user = self.users.find(f"id={self.user.id}")
        self.assertTrue(len(user.reset_key) > 40)
        self.assertEquals(['create', 'request_password_reset', 'update'], [audit.action for audit in user.audit])

    def test_failure(self):
        response = self.login(body={
            'email': 'noone@example.com',
        })
        self.assertEquals({}, response[0]['data'])
        self.assertEquals(200, response[1])

        user = self.users.find(f"id={self.user.id}")
        self.assertEquals(None, user.reset_key)
        self.assertEquals(['create'], [audit.action for audit in user.audit])
