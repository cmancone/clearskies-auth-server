import hashlib
from clearskies.input_requirements import Requirement


class HaveIBeenPwned(Requirement):
    def __init__(self, requests):
        self.requests = requests

    def configure(self):
        pass

    def check(self, model, data):
        if not data.get(self.column_name):
            return ""
        hashed = hashlib.sha1(data.get(self.column_name).encode("utf-8")).hexdigest().upper()
        response = self.requests.get("https://api.pwnedpasswords.com/range/" + hashed[:5])
        if hashed[5:] in response.content.decode("utf-8"):
            return "That password has been leaked in a previous data breach.  I'm afraid you'll have to pick a different password."
        return ""
