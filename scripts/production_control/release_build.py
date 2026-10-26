#!/usr/bin/env python3
"""Prepare an offline, versioned Agent/WebUI pair. Never stop or change a service.

Run after testing exact source commits. This copies a working Python distribution
and installed dependencies; it does not resolve or install packages from a network.
The output manifest is a candidate, not an activation or health receipt.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import time

import production_launcher as launcher


def run(argv, **kwargs):
    return subprocess.check_output(argv, text=True, stderr=subprocess.PIPE, timeout=180, **kwargs).strip()


def git(repo, *args):
    return run(['/usr/bin/git', '-C', str(repo), *args])


def snapshot(source, ref, destination):
    sha = git(source, 'rev-parse', '--verify', ref + '^{commit}')
    destination.mkdir()
    git(destination, 'init', '--quiet')
    git(destination, 'fetch', '--quiet', '--depth=1', '--no-tags', str(source), sha)
    git(destination, 'checkout', '--quiet', '--detach', 'FETCH_HEAD')
    if git(destination, 'rev-parse', 'HEAD') != sha:
        raise RuntimeError('Snapshot identity mismatch')
    return sha


def ignore_runtime(directory, names):
    return [name for name in names if name == '__pycache__' or name.endswith('.pyc') or
            name.startswith('__editable__')]


def _clear_runtime_flags(fd, flags):
    if not flags:
        return
    # CPython on macOS exposes chflags(path), but not fchflags(fd). Never
    # fall back to a path operation after opening and validating an inode.
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    fchflags = libc.fchflags
    fchflags.argtypes = (ctypes.c_int, ctypes.c_uint)
    fchflags.restype = ctypes.c_int
    if fchflags(fd, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))


def normalize_runtime_copy(path):
    """Unseal only owned destination inodes, never symlinks or shared files.

    The caller must supply an exclusively held disposable copy under trusted
    ancestors (no concurrent same-UID/privileged writers, hostile mounts or
    ACL-granted writers). POSIX modes cannot establish that trust. Failures
    leave a partially normalized *destination* and must abort the build.
    Symlinks are preserved untouched; later inventory admission owns their
    target policy. copytree creates independent files, so reject ALL hardlinks.
    """
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    path = Path(path).absolute()
    if '..' in path.parts or path == Path(path.anchor):
        raise RuntimeError('Runtime copy must be a concrete destination directory')

    def validate(info, device):
        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
            raise RuntimeError('Unsupported runtime copy entry')
        if info.st_uid != os.geteuid() or info.st_mode & 0o022:
            raise RuntimeError('Runtime copy entry is not exclusively owned')
        if info.st_dev != device:
            raise RuntimeError('Runtime copy crosses a filesystem boundary')
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise RuntimeError('Hardlinked runtime copy entry')

    def normalize(fd, device):
        info = os.fstat(fd)
        validate(info, device)
        _clear_runtime_flags(fd, getattr(info, 'st_flags', 0))
        mode = stat.S_IMODE(info.st_mode) | stat.S_IWUSR
        os.fchmod(fd, mode)
        after = os.fstat(fd)
        if stat.S_IMODE(after.st_mode) != mode or getattr(after, 'st_flags', 0):
            raise RuntimeError('Runtime copy normalization did not take effect')
        if not stat.S_ISDIR(info.st_mode):
            return
        for name in os.listdir(fd):
            entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISLNK(entry.st_mode):
                continue
            validate(entry, device)
            flags = directory_flags if stat.S_ISDIR(entry.st_mode) else (
                os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
            child = os.open(name, flags, dir_fd=fd)
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (entry.st_dev, entry.st_ino):
                    raise RuntimeError('Runtime copy entry changed during traversal')
                normalize(child, device)
            finally:
                os.close(child)

    # Open every ancestor without following links, retaining the final handle.
    # Ancestors are never chmodded; a symlink anywhere in the input fails closed.
    fd = os.open(path.anchor, directory_flags)
    try:
        for component in path.parts[1:]:
            child = os.open(component, directory_flags, dir_fd=fd)
            os.close(fd)
            fd = child
        normalize(fd, os.fstat(fd).st_dev)
    finally:
        os.close(fd)


def private_python(source_python, root, *, runner=None, source_root=None):
    runner = runner or run
    info = json.loads(runner([str(source_python), '-B', '-s', '-c',
        'import json,sys,sysconfig; print(json.dumps({"base":sys.base_prefix,"site":sysconfig.get_paths()["purelib"]}))']))
    if source_root is not None:
        for name in ('base', 'site'):
            if not Path(info[name]).resolve().is_relative_to(source_root.resolve()):
                raise RuntimeError('Interpreter metadata escapes source runtime')
    base = root / 'python'
    shutil.copytree(Path(info['base']).resolve(), base, symlinks=True, ignore=ignore_runtime)
    normalize_runtime_copy(base)
    python = base / 'bin' / 'python3'
    venv = root / 'venv'
    runner([str(python), '-B', '-s', '-m', 'venv', '--without-pip', str(venv)], env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'})
    executable = venv / 'bin' / 'python'
    site = Path(runner([str(executable), '-B', '-s', '-c', 'import sysconfig; print(sysconfig.get_paths()["purelib"])']))
    if not site.resolve().is_relative_to(root.resolve()):
        raise RuntimeError('Interpreter site path escapes destination runtime')
    shutil.copytree(info['site'], site, dirs_exist_ok=True, symlinks=True, ignore=ignore_runtime)
    normalize_runtime_copy(site)
    # Replace all console-script launchers with the preserved package entry points
    # so child tools cannot fall through to a development interpreter on PATH.
    command = '''import importlib.metadata,json
print(json.dumps({e.name:e.value for d in importlib.metadata.distributions() for e in d.entry_points if e.group == "console_scripts"}))'''
    entries = json.loads(runner([str(executable), '-B', '-s', '-c', command]))
    for name, value in entries.items():
        if '/' in name or ':' not in value:
            continue
        module, symbol = value.split(':', 1)
        symbol = symbol.split(' [', 1)[0]
        script = venv / 'bin' / name
        script.write_text(f'#!{executable}\nimport importlib,sys\nobj=importlib.import_module({module!r})\n'
                          f'for part in {symbol!r}.split("."): obj=getattr(obj,part)\n'
                          'if __name__ == "__main__": sys.exit(obj())\n')
        script.chmod(0o755)
    return executable


def _chmod_readonly(root, skip=None):
    for directory, dirs, files in os.walk(root, topdown=True):
        if skip is not None:
            dirs[:] = [d for d in dirs if Path(directory) / d != skip]
        for name in files:
            path = Path(directory) / name
            if not path.is_symlink():
                path.chmod(path.stat().st_mode & ~0o222)
        Path(directory).chmod(Path(directory).stat().st_mode & ~0o222)


def _refresh_git_index(root):
    """Re-stat tracked files so cheap probes (diff-index) agree with the bytes.

    Sealing changes every file's ctime, which leaves the index's cached stat
    data stale: `git diff-index --quiet HEAD` then reports all files modified
    and version badges read `-dirty` on a byte-identical checkout. Must run
    after the work tree is sealed (no further ctime changes) and before .git
    is sealed (the refresh rewrites .git/index).
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
    subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', 'update-index', '-q', '--refresh'],
                   cwd=root, env=env, capture_output=True, check=False)
    dirty = subprocess.run(['git', 'diff-index', '--quiet', 'HEAD', '--'],
                           cwd=root, env=env, capture_output=True)
    if dirty.returncode != 0:
        raise RuntimeError(f'Sealed checkout is not clean against HEAD: {root}')


def seal(root):
    """Discourage in-place edits; deployment produces another directory instead."""
    root = Path(root)
    git_dir = root / '.git'
    if git_dir.is_dir() and not git_dir.is_symlink():
        _chmod_readonly(root, skip=git_dir)
        _refresh_git_index(root)
        _chmod_readonly(git_dir)
    else:
        _chmod_readonly(root)


def build(args):
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    source_paths = {'agent': args.agent_repo.resolve(), 'webui': args.webui_repo.resolve()}
    refs = {'agent': args.agent_ref, 'webui': args.webui_ref}
    commits = {name: snapshot(source, refs[name], root / name) for name, source in source_paths.items()}
    runtime = root / 'runtime'
    # Do not resolve a venv's executable symlink: that loses its site-packages.
    python = private_python(args.python.absolute(), runtime)
    state = args.state_dir.resolve()
    agent = root / 'agent'
    webui = root / 'webui'
    env = {'HERMES_HOME': str(state), 'HERMES_BASE_HOME': str(state),
           'PYTHONPATH': str(agent), 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONNOUSERSITE': '1',
           'VIRTUAL_ENV': str(python.parent.parent),
           'PATH': str(python.parent) + ':' + os.environ.get('PATH', '/usr/bin:/bin'),
           'HERMES_WEBUI_AGENT_DIR': str(agent), 'HERMES_WEBUI_AUTO_INSTALL': '0',
           'HERMES_WEBUI_FOREGROUND': '1', 'HERMES_WEBUI_STATE_DIR': str(state / 'webui')}
    services = {
        'agent': {'repo': str(agent), 'cwd': str(state),
                  'argv': [str(python), '-m', 'hermes_cli.stderr_timestamp', '--error-log',
                           str(state / 'logs/gateway.error.log'), '--', str(python), '-m',
                           'hermes_cli.main', 'gateway', 'run', '--external-supervisor'],
                  'requires': [], 'probe_modules': ['hermes_cli.main', 'run_agent']},
        'webui': {'repo': str(webui), 'cwd': str(webui),
                  'argv': [str(python), str(webui / 'server.py')], 'requires': ['agent'],
                  'probe_modules': ['api.config', 'server'], 'env_files': [str(args.webui_env.resolve())]},
    }
    # The local manager, not generic install/update, owns release activation.
    for name, item in services.items():
        service_env = dict(env, PYTHONSAFEPATH='1')
        if name == 'webui':
            service_env['PYTHONPATH'] = str(webui) + os.pathsep + str(agent)
        item.update(env=service_env, commit=commits[name],
                    version=git(root / name, 'describe', '--tags', '--always'),
                    plist_path=str(Path.home() / 'Library/LaunchAgents' /
                                   ('ai.hermes.gateway.plist' if name == 'agent' else 'com.charles.hermes-webui.plist')))
    seal(agent)
    seal(webui)
    seal(runtime)
    runtime_descriptor = {'root': str(runtime), 'inventory': launcher.inventory(runtime)}
    for item in services.values():
        item['inventory'] = launcher.inventory(item['repo'])
    services['agent']['runtimes'] = [runtime_descriptor]
    manifest = {'schema_version': 2, 'release_id': root.name, 'prepared_at': time.time(),
                'state_dir': str(state), 'health_url': args.health_url,
                'labels': {'agent': 'ai.hermes.gateway', 'webui': 'com.charles.hermes-webui'},
                'source_commits': commits, 'services': services,
                'verification_note': str(args.verification_note.resolve())}
    launcher.preflight(manifest)
    target = root / 'release.json'
    target.write_text(json.dumps(manifest, indent=2) + '\n')
    target.chmod(0o444)
    print(json.dumps({'status': 'prepared_not_activated', 'manifest': str(target), 'commits': commits}))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('agent-repo', 'webui-repo', 'python', 'output', 'state-dir', 'webui-env', 'verification-note'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--agent-ref', default='HEAD')
    parser.add_argument('--webui-ref', default='HEAD')
    parser.add_argument('--health-url', default='http://127.0.0.1:8787/health')
    args = parser.parse_args()
    if not args.verification_note.is_file():
        parser.error('An existing verification note is required; preparation is not test certification')
    build(args)


if __name__ == '__main__':
    main()
