from clearskies.column_types import build_column_config
from .password import Password
def password(name, **kwargs):
    return build_column_config(name, Password, **kwargs)
