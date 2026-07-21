"""Runtime platform guard for the only supported MVP target."""

from pathlib import Path


class UnsupportedPlatformError(RuntimeError):
    """The agent was started outside Ubuntu Server 24.04 LTS."""


def require_ubuntu_2404(os_release_path: Path = Path("/etc/os-release")) -> None:
    """Reject unverified platforms before opening journald or the spool."""

    try:
        values = _parse_os_release(os_release_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as error:
        raise UnsupportedPlatformError("Ubuntu 24.04 platform could not be verified") from error
    if values.get("ID") != "ubuntu" or values.get("VERSION_ID") != "24.04":
        raise UnsupportedPlatformError("only Ubuntu Server 24.04 LTS is supported")


def _parse_os_release(contents: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for raw_line in contents.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", maxsplit=1)
        result[key] = value.strip().strip('"')
    return result
