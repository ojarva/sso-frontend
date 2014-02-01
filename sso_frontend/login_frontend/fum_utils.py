import slumber
import slumber.auth

class FUM:
    def __init__(self, url, token):
        self.api = slumber.API(url, auth=slumber.auth.TokenAuth(token))

    def get_phone_numbers(self, username):
        
