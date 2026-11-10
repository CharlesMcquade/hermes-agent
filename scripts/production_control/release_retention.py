#!/usr/bin/env python3
"""Archive superseded frozen releases while retaining current, N-1 and live anchors.

Dry-run by default. --apply moves eligible trees into a same-volume recycle
folder after content verification; it never empties that folder or restarts a service.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time
from typing import Any

SCHEMA_VERSION = 1
LIVE_MAINTENANCE_FILES = (
    'control-install.json', 'native-install-receipt.json',
    'native-control-refresh-receipt.json', 'webui-watchdog.sh',
    'pending-user-restart.json', 'activation-transaction.json', 'resilient-cutover.plist',
)


def encoded(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True) + '\n').encode()


def file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def tree_digest(root: Path) -> str:
    """Content digest independent of rename and top-level write-bit adjustment."""
    result = hashlib.sha256()
    for base, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        files.sort()
        for name in sorted(dirs + files):
            path = Path(base) / name
            relative = path.relative_to(root).as_posix().encode()
            if path.is_symlink():
                payload = b'L\0' + os.readlink(path).encode()
            elif path.is_dir():
                payload = b'D\0'
            elif path.is_file():
                size = path.stat().st_size
                result.update(len(relative).to_bytes(8, 'big'))
                result.update(relative)
                result.update(b'F\0')
                result.update(size.to_bytes(8, 'big'))
                with path.open('rb') as source:
                    for chunk in iter(lambda: source.read(1024 * 1024), b''):
                        result.update(chunk)
                continue
            else:
                raise RuntimeError('Unsupported release payload type: ' + str(path))
            result.update(len(relative).to_bytes(8, 'big'))
            result.update(relative)
            result.update(len(payload).to_bytes(8, 'big'))
            result.update(payload)
    return result.hexdigest()


def tree_stats(root: Path) -> tuple[int, int]:
    count = 0
    size = 0
    for base, dirs, files in os.walk(root, followlinks=False):
        for name in files:
            path = Path(base) / name
            if not path.is_symlink():
                count += 1
                size += path.stat().st_size
    return count, size


def read_text(path: Path) -> str:
    try:
        if path.is_file() and not path.is_symlink() and path.stat().st_size <= 20_000_000:
            return path.read_text(errors='replace')
    except OSError:
        pass
    return ''


def collect_live_texts(home: Path | None = None) -> dict[str, str]:
    home = home or Path.home()
    maintenance = home / '.hermes/maintenance'
    result = {}
    for name in LIVE_MAINTENANCE_FILES:
        result['maintenance/' + name] = read_text(maintenance / name)
    # bootstrap_python is sealed into Verity.app, not repeated in the selected
    # release manifest. It is a live dependency even when its release is old.
    settings = (home / 'Applications/Verity.app/Contents/Resources'
                / 'service-settings.json')
    result['native-app/service-settings.json'] = read_text(settings)
    for path in (home / 'Library/LaunchAgents').glob('*.plist'):
        result['launchagent/' + path.name] = read_text(path)
    for path in maintenance.glob('*.py'):
        result['maintenance-script/' + path.name] = read_text(path)
    scripts = home / '.hermes/scripts'
    if scripts.is_dir():
        for path in scripts.rglob('*.py'):
            result['hermes-script/' + str(path.relative_to(scripts))] = read_text(path)
    config_paths = [home / '.hermes/config.yaml', home / '.hermes/cron/jobs.json']
    config_paths.extend((home / '.hermes/profiles').glob('*/config.yaml'))
    config_paths.extend((home / '.hermes/profiles').glob('*/cron/jobs.json'))
    for path in config_paths:
        result['config/' + str(path.relative_to(home))] = read_text(path)
    try:
        result['processes'] = subprocess.check_output(
            ['ps', '-axo', 'args='], text=True, stderr=subprocess.DEVNULL, timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        result['processes'] = ''
    return result


def live_reference_reasons(root: Path, live_texts: dict[str, str]) -> list[str]:
    value = str(root)
    return sorted(label for label, text in live_texts.items() if value in text)


def retention_plan(
    releases: Path, selected_manifest: Path, live_texts: dict[str, str] | None = None,
) -> dict[str, Any]:
    live_texts = collect_live_texts() if live_texts is None else live_texts
    selected_bytes = selected_manifest.read_bytes()
    selected = json.loads(selected_bytes)
    selected_sha = hashlib.sha256(selected_bytes).hexdigest()
    baseline_sha = selected.get('baseline_sha256')
    candidates = []
    for root in sorted(releases.iterdir()):
        if not root.is_dir() or root.is_symlink():
            continue
        manifest = root / 'release.json'
        if not manifest.is_file() or manifest.is_symlink():
            raise RuntimeError('Release lacks a regular manifest: ' + str(root))
        item = json.loads(manifest.read_text())
        if item.get('release_id') != root.name:
            raise RuntimeError('Release id/path mismatch: ' + str(root))
        candidates.append((root, manifest))
    previous = [root for root, manifest in candidates if file_digest(manifest) == baseline_sha]
    # A release built from a run-directory candidate can leave N-1 outside the
    # canonical releases root. runtime.source identifies that previous release's
    # private interpreter; prove it by matching the selected baseline hash too.
    runtime_source = selected.get('runtime', {}).get('source')
    if runtime_source:
        for ancestor in Path(runtime_source).parents:
            if ancestor.name != 'runtime':
                continue
            external = ancestor.parent / 'release.json'
            if external.is_file() and file_digest(external) == baseline_sha:
                previous.append(external.parent)
            break
    if len(previous) != 1:
        raise RuntimeError(
            'Cannot prove exactly one N-1 rollback from the selected manifest baseline_sha256; '
            'archive nothing and repair the retention chain'
        )
    # repos are <release>/<agent|webui>, so their parent is the release root.
    selected_roots = {Path(service['repo']).parent for service in selected.get('services', {}).values()
                      if service.get('repo')}
    external = []
    if not previous[0].is_relative_to(releases):
        external.append({'path': str(previous[0]), 'reasons': ['N-1']})
    external.extend({'path': str(root), 'reasons': ['selected-current']}
                    for root in sorted(selected_roots) if not root.is_relative_to(releases))
    plan = {
        'schema_version': SCHEMA_VERSION,
        'selected_release_id': selected.get('release_id'),
        'selected_manifest': str(selected_manifest),
        'selected_manifest_sha256': selected_sha,
        'releases_root': str(releases),
        'policy': 'current+N-1+live-operational-anchors; recycle-never-delete',
        'keep': [], 'archive': [], 'retained_outside_releases_root': external,
    }
    for root, manifest in candidates:
        name = root.name
        reasons = []
        if root in selected_roots:
            reasons.append('selected-current')
        if root == previous[0]:
            reasons.append('N-1')
        reasons.extend(live_reference_reasons(root, live_texts))
        record = {'release_id': name, 'path': str(root), 'reasons': sorted(set(reasons))}
        if reasons:
            plan['keep'].append(record)
            continue
        count, size = tree_stats(root)
        record.update({
            'files': count, 'bytes': size, 'tree_sha256': tree_digest(root),
            'manifest_sha256': file_digest(manifest),
        })
        plan['archive'].append(record)
    plan['archive_bytes'] = sum(item['bytes'] for item in plan['archive'])
    plan['note'] = 'Trash relocation does not reclaim disk until separately emptied.'
    return plan


def unlock_top_directory(path: Path) -> None:
    # release_build.seal may apply both a read-only mode and UF_IMMUTABLE.
    # Only the top directory needs changing for a rename; payload stays sealed.
    flags = getattr(path.stat(), 'st_flags', 0)
    if flags and hasattr(os, 'chflags'):
        os.chflags(path, flags & ~getattr(stat, 'UF_IMMUTABLE', 2), follow_symlinks=False)
    path.chmod(stat.S_IMODE(path.stat().st_mode) | stat.S_IWUSR)


def restore_top_directory(path: Path, mode: int, flags: int) -> None:
    path.chmod(mode)
    if flags and hasattr(os, 'chflags'):
        os.chflags(path, flags, follow_symlinks=False)


def apply_plan(plan: dict[str, Any], archive_root: Path, receipt_path: Path) -> dict[str, Any]:
    selected_manifest = Path(plan['selected_manifest'])
    if file_digest(selected_manifest) != plan['selected_manifest_sha256']:
        raise RuntimeError('Selected manifest changed since retention planning')
    releases = Path(plan['releases_root'])
    live_texts = collect_live_texts()
    for item in plan['archive']:
        root = releases / item['release_id']
        reasons = live_reference_reasons(root, live_texts)
        if reasons:
            raise RuntimeError('Release gained a live reference since planning: ' + str(root) + ' ' + ','.join(reasons))
        if not root.is_dir():
            raise RuntimeError('Release changed since planning: ' + str(root))
        if tree_digest(root) != item['tree_sha256']:
            raise RuntimeError('Release contents changed since planning: ' + str(root))
    if archive_root.exists():
        raise RuntimeError('Archive batch already exists: ' + str(archive_root))
    if archive_root.parent.exists() and archive_root.parent.stat().st_dev != releases.stat().st_dev:
        raise RuntimeError('Archive must be on the same volume for restorable atomic moves')
    archive_root.mkdir(parents=True)
    moved = []
    modes = {}
    flags = {}
    try:
        for item in plan['archive']:
            name = item['release_id']
            source = releases / name
            target = archive_root / name
            modes[name] = stat.S_IMODE(source.stat().st_mode)
            flags[name] = getattr(source.stat(), 'st_flags', 0)
            try:
                unlock_top_directory(source)
                os.rename(source, target)
            except Exception:
                # A refused rename must not leave the original top directory
                # writable or with its immutable flag stripped.
                restore_top_directory(source, modes[name], flags[name])
                raise
            moved.append(name)
            restore_top_directory(target, modes[name], flags[name])
            if tree_digest(target) != item['tree_sha256']:
                raise RuntimeError('Archived byte verification failed: ' + name)
    except Exception:
        errors = []
        for name in reversed(moved):
            source = archive_root / name
            target = releases / name
            try:
                unlock_top_directory(source)
                os.rename(source, target)
                restore_top_directory(target, modes[name], flags[name])
            except Exception as restore_error:
                errors.append(name + ': ' + str(restore_error))
        if errors:
            raise RuntimeError('Archive failed and restoration was incomplete: ' + '; '.join(errors))
        raise
    receipt = {
        'schema_version': SCHEMA_VERSION, 'status': 'archived', 'finished_at': time.time(),
        'selected_release_id': plan['selected_release_id'],
        'selected_manifest_sha256': plan['selected_manifest_sha256'],
        'archive_root': str(archive_root), 'releases_root': str(releases),
        'moved': moved, 'kept': plan['keep'], 'archive_bytes': plan['archive_bytes'],
        'bytes_reclaimed': 0,
        'restore': 'Move each named tree back to releases_root with its original directory name.',
        'note': plan['note'],
    }
    receipt_path.parent.mkdir(parents=True, exist_ok=True)
    receipt_path.write_bytes(encoded(receipt))
    (archive_root / 'RETENTION-RECEIPT.json').write_bytes(encoded(receipt))
    if file_digest(selected_manifest) != plan['selected_manifest_sha256']:
        raise RuntimeError('Selected manifest changed during archival; do not empty the recycle folder')
    return receipt


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    home = Path.home()
    parser.add_argument('--releases', type=Path, default=home / '.hermes/releases')
    parser.add_argument('--manifest', type=Path, default=home / '.hermes/maintenance/production-release.json')
    parser.add_argument('--archive-root', type=Path)
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    try:
        plan = retention_plan(args.releases, args.manifest)
        if not args.apply:
            print(json.dumps(plan, indent=2, sort_keys=True))
            return 0
        stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        archive_root = args.archive_root or home / ('.Trash/hermes-release-archive-' + stamp)
        receipt_path = args.receipt or home / ('.hermes/maintenance/release-retention/' + stamp + '.json')
        receipt = apply_plan(plan, archive_root, receipt_path)
        print(json.dumps(receipt, indent=2, sort_keys=True))
        return 0
    except Exception as exc:
        print(json.dumps({'status': 'NOT_ARCHIVED', 'error': str(exc)}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
