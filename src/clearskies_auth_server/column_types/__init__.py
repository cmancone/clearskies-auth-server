from clearskies.column_types import build_column_config
from .password import Password
from .tenant_id import TenantId


def password(name, **kwargs):
    return build_column_config(name, Password, **kwargs)


def tenant_id(name, **kwargs):
    return build_column_config(name, TenantId, **kwargs)


__all__ = [
    "password",
    "Password",
    "tenant_id",
    "TenantId",
]
