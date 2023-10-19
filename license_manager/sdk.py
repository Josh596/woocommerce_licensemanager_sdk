import datetime
from dataclasses import dataclass, fields
from enum import Enum
from typing import Any, Callable, Optional, Type
from urllib.parse import urljoin

import requests
from exceptions import (
    ActivationLimitReachedException,
    APIException,
    ExpiredLicenseKeyException,
    InvalidLicenseKeyException,
)
from typing_extensions import Self


class HttpMethod(Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"

    def request(self) -> Callable[..., requests.Response]:
        method_map = {
            HttpMethod.GET: requests.get,
            HttpMethod.POST: requests.post,
            HttpMethod.PUT: requests.put,
        }

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
    created_at: datetime.date

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
        created_at = data["createdAt"]

        return License(
            license_key=license_key,
            expires_at=expires_at,
            times_activated=times_activated,
            times_activated_max=times_activated_max,
            created_at=created_at,
        )

    def _build_license_from_response(self, response):
        return self._build_license_from_dict(response["data"])

    def _make_license_request(self, sub_route: str, method=HttpMethod.GET, **kwargs):
        endpoint = f"licenses/{sub_route}"
        try:
            response = self._make_request(method, endpoint=endpoint, **kwargs)
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

    def license_update(self, license_key: str, data: dict):
        sub_route = f"{license_key}"
        license = self._make_license_request(
            sub_route, method=HttpMethod.PUT, data=data
        )

        return license
        ...
