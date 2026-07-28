"""Safe HTML boundary errors."""


class WebError(Exception):
    """An intentional Dashboard response without internal exception details."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail
