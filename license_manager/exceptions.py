class APIException(Exception):
    ...


class InvalidLicenseKeyException(APIException):
    ...


class ExpiredLicenseKeyException(APIException):
    ...


class ActivationLimitReachedException(APIException):
    ...
