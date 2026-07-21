"""Safe API errors that include a request identifier without internal details."""

from collections.abc import Mapping


class ApiError(Exception):
    """An expected API failure safe to expose to an unauthenticated caller."""

    def __init__(
        self,
        status_code: int,
        detail: str,
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
        self.headers = dict(headers or {})
