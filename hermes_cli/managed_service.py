"""Local launchd ownership contract for external deployment managers.

HermesServiceManager is a top-level plist dictionary with a nonempty description
and preflight argv (absolute executable, followed by literal string arguments).
The manager owns the definition; Hermes may start/restart it only after preflight.
Never execute this contract through a shell or silently downgrade invalid metadata.
"""
import os
import plistlib
import subprocess
from dataclasses import dataclass
from pathlib import Path


class ManagedServiceError(RuntimeError):
    """An external service manager prevented an unsafe lifecycle operation."""


@dataclass(frozen=True)
class ServiceManager:
    preflight: tuple[str, ...]
    description: str

    def check(self) -> None:
        try:
            result = subprocess.run(
                list(self.preflight), check=False, shell=False, timeout=60,
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                errors="replace",
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ManagedServiceError(
                f"Externally managed service preflight could not complete: {exc}. {self.description}"
            ) from exc
        if result.returncode:
            detail = (result.stderr or result.stdout or "").strip()
            raise ManagedServiceError(
                f"Externally managed service preflight failed (exit {result.returncode}): "
                f"{detail}. {self.description}"
            )


def read_service_manager(path: Path) -> ServiceManager | None:
    try:
        with path.open("rb") as stream:
            data = plistlib.load(stream)
    except FileNotFoundError:
        return None
    except (OSError, ValueError, plistlib.InvalidFileException) as exc:
        raise ManagedServiceError(
            f"Cannot determine externally managed service ownership of {path}: {exc}"
        ) from exc
    # A successfully parsed non-dictionary has no top-level ownership key.
    # Leave legacy repair behavior intact for such unmanaged definitions.
    if not isinstance(data, dict) or "HermesServiceManager" not in data:
        return None
    marker = data["HermesServiceManager"]
    if isinstance(marker, dict):
        argv, description = marker.get("preflight"), marker.get("description")
        if (isinstance(argv, list) and argv
                and all(isinstance(arg, str) and arg and "\0" not in arg for arg in argv)
                and os.path.isabs(argv[0])
                and isinstance(description, str) and description.strip()):
            return ServiceManager(tuple(argv), description)
    raise ManagedServiceError(
        f"Invalid HermesServiceManager in externally managed service {path}; "
        "use its deployment manager to repair the marker (absolute executable argv and description required)"
    )


def preserve_service_definition(path: Path, *, refuse: bool = False) -> bool:
    """Refuse install, or skip automatic refresh, without executing manager code."""
    try:
        manager = read_service_manager(path)
        if manager is None:
            return False
        message = f"Externally managed service at {path}; {manager.description}"
    except ManagedServiceError as exc:
        message = str(exc)
    if refuse:
        raise ManagedServiceError(message)
    print(f"↻ Preserving externally managed service definition: {message}")
    return True


def preflight_service(path: Path) -> ServiceManager | None:
    manager = read_service_manager(path)
    if manager is not None:
        print(f"Externally managed service: {manager.description}")
        manager.check()
    return manager
