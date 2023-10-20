import datetime
from dataclasses import dataclass, fields
from enum import Enum
from typing import Any, Callable, Optional, Type
from urllib.parse import urljoin

import requests
from typing_extensions import Self

from .exceptions import (
    ActivationLimitReachedException,
    APIException,
    ExpiredLicenseKeyException,
    InvalidLicenseKeyException,
)


class HttpMethod(Enum):
    GET = "GET"
    POST = "POST"

    def request(self) -> Callable[..., requests.Response]:
        method_map = {HttpMethod.GET: requests.get, HttpMethod.POST: requests.post}

        return method_map[self]
        ...


class LicenseExceptionFactory:
    license_expired_code = "lmfwc_rest_license_expired"
    invalid_license_code = "lmfwc_rest_data_error"
    # Note: This is a custom code. The API does not have this code. It uses "lmfwc_rest_data_error" for both
    # activation limit and invalid license key.
    activation_limit_code = "lmfwc_rest_activation_limit"

    error_code_map = {
        license_expired_code: ExpiredLicenseKeyException,
        invalid_license_code: InvalidLicenseKeyException,
        activation_limit_code: ActivationLimitReachedException,
    }

    @classmethod
    def get_exception(cls, error_code: str, error_message: str) -> APIException:
        error_code = error_code.lower()
        if (
            "maximum activation count" in error_message.lower()
            and error_code == cls.invalid_license_code
        ):
            error_code = cls.activation_limit_code
        exception_class: APIException = cls.error_code_map.get(error_code, APIException)
        return exception_class(error_message)


@dataclass
class License:
    license_key: str
    expires_at: datetime.datetime
    times_activated: int
    times_activated_max: int
    created_at: datetime.datetime

    def is_expired(self):
        return datetime.datetime.utcnow() > self.expires_at


class LicenseManager:
    _CONTENT_TYPE = "application/json"

    def __init__(self, consumer_key: str, consumer_secret: str, site_url: str):
        self._consumer_key = consumer_key
        self._consumer_secret = consumer_secret
        self.BASE_ENDPOINT = urljoin(site_url, "wp-json/lmfwc/v2/")

    def _url(self, path: str):
        return urljoin(self.BASE_ENDPOINT, path)

    def _headers(self):
        return {
            "Content-Type": self._CONTENT_TYPE,
            "user-agent": "license_manager-sdk",
        }

    def _make_request(
        self,
        method: HttpMethod,
        endpoint: str,
        query_params: Optional[dict] = None,
        data: Optional[dict] = None,
    ):
        response = method.request()(
            url=self._url(endpoint),
            headers=self._headers(),
            params=query_params,
            json=data,
            auth=(self._consumer_key, self._consumer_secret),
        )
        response.raise_for_status()
        return response.json()

    def _build_license_from_dict(self, data: dict):
        license_key = data["licenseKey"]
        expires_at = datetime.datetime.fromisoformat(data["expiresAt"]).replace(
            tzinfo=datetime.timezone.utc
        )
        times_activated = data["timesActivated"]
        times_activated_max = data["timesActivatedMax"]
        created_at = datetime.datetime.fromisoformat(data["createdAt"]).replace(
            tzinfo=datetime.timezone.utc
        )

        return License(
            license_key=license_key,
            expires_at=expires_at,
            times_activated=times_activated,
            times_activated_max=times_activated_max,
            created_at=created_at,
        )

    def _build_license_from_response(self, response):
        return self._build_license_from_dict(response["data"])

    def _make_license_request(self, sub_route: str):
        endpoint = f"licenses/{sub_route}"
        try:
            response = self._make_request(HttpMethod.GET, endpoint=endpoint)
        except requests.HTTPError as err:
            err_json = err.response.json()
            code = err_json["code"]
            message = err_json["message"]

            raise LicenseExceptionFactory.get_exception(
                error_code=code, error_message=message
            )
        license = self._build_license_from_response(response)
        return license

    def license_get_info(self, license_key: str) -> License:
        sub_route = f"{license_key}"
        license = self._make_license_request(sub_route)

        return license

    def license_activate(self, license_key: str) -> License:
        sub_route = f"activate/{license_key}"

        license = self._make_license_request(sub_route)

        return license

    def license_deactivate(self, license_key: str) -> License:
        sub_route = f"deactivate/{license_key}"

        license = self._make_license_request(sub_route)

        return license


if __name__ == "__main__":
    consumer_key = "ck_f1e671bfe697b3d6e2b67074dded8b0345592b20"
    consumer_secret = "cs_86d125b6a878b2cb50fc5866598ca8d08758edc1"

    site_url = "http://design-gecko.com"
    test_key = "IMG1YR2DM0-44YG-PFCP-37RL-SYS8"
    expired_key = "IMG1MI6T2-F6KB-A5TN-U0AP-VD"

    test_key = expired_key
    license_manager = LicenseManager(consumer_key, consumer_secret, site_url)

    license_data = license_manager.license_deactivate(license_key=test_key)
    license_data = license_manager.license_activate(license_key=test_key)


# 'lmfwc_rest_license_expired'
# 'lmfwc_rest_data_error'
