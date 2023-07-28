from clearskies import BindingConfig
from .jwks_direct import JwksDirect


def jwks_direct(path_to_public_keys, **kwargs):
    return BindingConfig(JwksDirect, path_to_public_keys=path_to_public_keys, **kwargs)


__all__ = [
    "JwksDirect",
    "jwks_direct",
]
