"""ChatGPT login profile facade — enforces uniform Chrome fingerprint."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping

from curl_cffi.requests import AsyncSession, Response


@dataclass(frozen=True)
class ChatgptLoginProfile:
    impersonate: str = "chrome142"
    user_agent: str = (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
    )
    sec_ch_ua: str = (
        '"Not:A-Brand";v="99", "Google Chrome";v="142", "Chromium";v="142"'
    )
    sec_ch_ua_mobile: str = "?0"
    sec_ch_ua_platform: str = '"macOS"'
    accept_language: str = "en-US,en;q=0.9"
    oai_language: str = "en-US"


CHATGPT_LOGIN_PROFILE = ChatgptLoginProfile()


def _merge_profile_headers(
    headers: Mapping[str, str] | None, profile: ChatgptLoginProfile
) -> dict[str, str]:
    """Merge caller headers with profile headers, case-insensitively."""
    merged: dict[str, str] = {}
    lower_map: dict[str, str] = {}

    if headers:
        for k, v in headers.items():
            lk = k.lower()
            merged[k] = v
            lower_map[lk] = k

    profile_entries = [
        ("User-Agent", profile.user_agent),
        ("sec-ch-ua", profile.sec_ch_ua),
        ("sec-ch-ua-mobile", profile.sec_ch_ua_mobile),
        ("sec-ch-ua-platform", profile.sec_ch_ua_platform),
    ]

    for p_key, p_val in profile_entries:
        lk = p_key.lower()
        if lk in lower_map:
            orig_key = lower_map[lk]
            if orig_key != p_key:
                del merged[orig_key]
        merged[p_key] = p_val
        lower_map[lk] = p_key

    if "accept-language" not in lower_map:
        merged["Accept-Language"] = profile.accept_language
        lower_map["accept-language"] = "Accept-Language"

    if "oai-language" not in lower_map:
        merged["oai-language"] = profile.oai_language
        lower_map["oai-language"] = "oai-language"

    return merged


class _ProfiledAsyncSessionFacade:
    """Wraps an AsyncSession to enforce Chrome headers on all calls."""

    def __init__(
        self,
        session: AsyncSession,
        profile: ChatgptLoginProfile = CHATGPT_LOGIN_PROFILE,
    ) -> None:
        self._session = session
        self._profile = profile
        if hasattr(session, "headers") and session.headers is not None:
            session.headers["User-Agent"] = profile.user_agent
            session.headers["sec-ch-ua"] = profile.sec_ch_ua
            session.headers["sec-ch-ua-mobile"] = profile.sec_ch_ua_mobile
            session.headers["sec-ch-ua-platform"] = profile.sec_ch_ua_platform
            session.headers.setdefault("Accept-Language", profile.accept_language)
            session.headers.setdefault("oai-language", profile.oai_language)

    @property
    def profile(self) -> ChatgptLoginProfile:
        return self._profile

    @property
    def cookies(self) -> Any:
        return self._session.cookies

    @property
    def headers(self) -> Any:
        return self._session.headers

    def __getattr__(self, name: str) -> Any:
        return getattr(self._session, name)

    async def get(self, url: str, **kwargs: Any) -> Response:
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> Response:
        return await self.request("POST", url, **kwargs)

    async def request(self, method: str, url: str, **kwargs: Any) -> Response:
        raw_headers = kwargs.get("headers")
        kwargs["headers"] = _merge_profile_headers(raw_headers, self._profile)
        if "impersonate" not in kwargs:
            kwargs["impersonate"] = self._profile.impersonate
        return await self._session.request(method, url, **kwargs)


def profile_chatgpt_login_http_client(
    client: AsyncSession, profile: ChatgptLoginProfile = CHATGPT_LOGIN_PROFILE
) -> AsyncSession:
    """Return a facade around client that enforces profile on every request."""
    if isinstance(client, _ProfiledAsyncSessionFacade):
        if client.profile == profile:
            return client  # type: ignore[return-value]
        return _ProfiledAsyncSessionFacade(client._session, profile)  # type: ignore[return-value]
    return _ProfiledAsyncSessionFacade(client, profile)  # type: ignore[return-value]


__all__ = [
    "ChatgptLoginProfile",
    "CHATGPT_LOGIN_PROFILE",
    "profile_chatgpt_login_http_client",
]
