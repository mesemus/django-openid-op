class OAuthError(BaseException):
    def __init__(self, error=None, error_description=None):
        self.error = error
        self.error_description = error_description