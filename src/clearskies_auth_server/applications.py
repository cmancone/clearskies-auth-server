from . import handlers
import clearskies


def key_manager(path_to_public_keys,
                path_to_private_keys,
                algorithm=None,
                key_type=None,
                key_size=None,
                authentication=None):
    handler_config = {
        'path_to_public_keys': path_to_public_keys,
        'path_to_private_keys': path_to_private_keys,
        'algorithm': algorithm,
        'key_type': key_type,
        'key_size': key_size,
    }
    handler_config = {
        key: value
        for (key, value) in handler_config.items() if value
    }

    routing_config = {
        'routes': [
            {
                'path': '',
                'handler_class': handlers.CreateKey,
                'handler_config': handler_config,
                'methods': ['POST'],
            },
            {
                'path': '',
                'handler_class': handlers.DeleteOldestKey,
                'handler_config': handler_config,
                'methods': ['DELETE'],
            },
            {
                'path': '',
                'handler_class': handlers.ListKeys,
                'handler_config': handler_config,
            },
            {
                'path': '{key_id}',
                'handler_class': handlers.DeleteKey,
                'handler_config': handler_config,
                'methods': ['DELETE'],
            },
        ],
    }
    if authentication:
        routing_config['authentication'] = authentication

    return clearskies.Application(
        clearskies.handlers.SimpleRouting,
        routing_config,
    )
