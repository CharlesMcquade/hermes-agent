"""Snapshot untrusted local media through trusted route-configured roots.

Descriptor-relative no-follow traversal closes the check/open race, including
intermediate directories. Downstream vision opens only a private cache copy.
Unsupported platforms fail closed rather than using a resolve-then-open fallback.
"""
import os
import re
from pathlib import Path
import stat
import tempfile

from hermes_constants import get_hermes_home

_MAX_IMAGE_BYTES = 20 * 1024 * 1024


def discard_snapshots(media):
    """Remove only private files created by this admission attempt."""
    for path, _ in media:
        Path(path).unlink(missing_ok=True)


def resolve_attachments(raw, roots, *, required=False):
    """Persistent messaging images are all-or-nothing; ordinary routes filter.

    An absent/empty list is a text turn. A supplied nonempty batch must import
    in full when required, including validation and root/access failures.
    """
    if raw is None or raw == []:
        return []
    supported = os.name == "posix" and hasattr(os, "O_NOFOLLOW")
    if not isinstance(raw, list) or not isinstance(roots, list) or not supported:
        if required:
            raise ValueError("Required attachment import unavailable")
        return []
    if required and len(raw) > 4:
        raise ValueError("Required attachment batch exceeds count limit")
    trusted = [Path(root) for root in roots
               if isinstance(root, str) and "\x00" not in root and Path(root).is_absolute()]
    out = []
    try:
        for item in raw[:4]:
            try:
                out.append(_import_attachment(item, trusted))
            except (OSError, ValueError):
                if required:
                    raise
        return out
    except BaseException:
        discard_snapshots(out)
        raise


def _import_attachment(item, trusted):
    if not isinstance(item, dict):
        raise ValueError("Invalid attachment")
    path, mime = item.get("path"), item.get("mime")
    if (not isinstance(path, str) or "\x00" in path or not Path(path).is_absolute()
            or ".." in Path(path).parts or not isinstance(mime, str)
            or re.fullmatch(r"image/[A-Za-z0-9.+-]+", mime) is None):
        raise ValueError("Invalid image attachment")
    for root in trusted:
        try:
            relative = Path(path).relative_to(root)
        except ValueError:
            continue
        if not relative.parts:
            continue
        try:
            return _snapshot(root, relative), mime
        except (OSError, ValueError):
            continue
    raise ValueError("Attachment could not be snapshotted through a trusted root")


def _snapshot(root, relative):
    # The root is operator-owned configuration; never expand a payload tilde or
    # resolve a payload symlink. O_NOFOLLOW also rejects a symlink root itself.
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    destination = None
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
        leaf = os.open(relative.parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
        with os.fdopen(leaf, "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > _MAX_IMAGE_BYTES:
                raise ValueError("Attachment must be a bounded regular file")
            cache = get_hermes_home() / "cache" / "webhook_attachments"
            cache.mkdir(parents=True, exist_ok=True, mode=0o700)
            with tempfile.NamedTemporaryFile(dir=cache, suffix=relative.suffix, delete=False) as target:
                destination = target.name
                # Bounded even if a concurrent writer grows the source after fstat.
                remaining = _MAX_IMAGE_BYTES + 1
                while remaining:
                    chunk = source.read(min(remaining, 65536))
                    if not chunk:
                        break
                    target.write(chunk)
                    remaining -= len(chunk)
                if remaining == 0:
                    raise ValueError("Attachment exceeds size limit")
        return destination
    except BaseException:
        if destination:
            Path(destination).unlink(missing_ok=True)
        raise
    finally:
        os.close(fd)
