import clearskies
from .profile_get import ProfileGet
from .profile_update import ProfileUpdate


class Profile(clearskies.handlers.Routing):
    _cached_handlers = None

    def __init__(self, di):
        super().__init__(di)
        self._cached_handlers = {}

    _configuration_defaults = {
        "base_url": "",
        "include_id_in_path": False,
        "allow_get": True,
        "allow_update": True,
        "get_handler": ProfileGet,
        "update_handler": ProfileUpdate,
        "get_request_method": "GET",
        "update_request_method": "PUT",
    }

    def handler_classes(self, configuration):
        classes = []
        for action in ["get", "update"]:
            allow_key = f"allow_{action}"
            handler_key = f"{action}_handler"
            if allow_key in configuration and not configuration[allow_key]:
                continue
            classes.append(
                configuration[handler_key]
                if handler_key in configuration
                else self._configuration_defaults[handler_key]
            )
        return classes

    def handle(self, input_output):
        handler_class = self._get_handler_class_for_route(input_output)
        if handler_class is None:
            return self.error(input_output, "Not Found", 404)
        handler = self.fetch_cached_handler(handler_class)
        return handler(input_output)

    def fetch_cached_handler(self, handler_class):
        cache_key = handler_class.__name__
        if cache_key not in self._cached_handlers:
            self._cached_handlers[cache_key] = self.build_handler(handler_class)
        return self._cached_handlers[cache_key]

    def _get_handler_class_for_route(self, input_output):
        request_method = input_output.get_request_method().upper()
        if request_method == self.configuration("get_request_method"):
            return self.configuration("get_handler") if self.configuration("allow_get") else None
        if request_method == self.configuration("update_request_method"):
            return self.configuration("update_handler") if self.configuration("allow_update") else None
        return None

    def cors(self, input_output):
        cors = self._cors_header
        if not cors:
            return self.error(input_output, "not found", 404)
        authentication = self._configuration.get("authentication")
        if authentication:
            authentication.set_headers_for_cors(cors)
        methods = {}
        for action in ["get", "update"]:
            if self.configuration(f"allow_{action}"):
                route_methods = self.configuration(f"{action}_request_method")
                if type(route_methods) != list:
                    route_methods = [route_methods]
                for route_method in route_methods:
                    methods[route_method] = True
        for method in methods.keys():
            cors.add_method(method)
        cors.set_headers_for_input_output(input_output)
        return input_output.respond("", 200)

    def documentation(self):
        docs = []
        for name in ["get", "update"]:
            if not self.configuration(f"allow_{name}"):
                continue
            handler = self.build_handler(self.configuration(f"{name}_handler"))
            action_docs = handler.documentation()
            for doc in action_docs:
                request_methods = self.configuration(f"{name}_request_method")
                doc.set_request_methods(request_methods if type(request_methods) == list else [request_methods])
                docs.append(doc)
        return docs

    def documentation_models(self):
        # read and write use the same model, so we just need one
        read_handler = self.build_handler(self.configuration("get_handler"))
        return read_handler.documentation_models()

    def documentation_security_schemes(self):
        # read and write use the same model, so we just need one
        read_handler = self.build_handler(self.configuration("get_handler"))
        return read_handler.documentation_security_schemes()
