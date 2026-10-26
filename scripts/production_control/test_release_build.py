"""Offline runtime preservation and source-environment regression tests."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import release_build as builder


class BuilderTests(unittest.TestCase):
    def test_symlink_virtualenv_metadata_comes_from_requested_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source'
            subprocess.run([sys.executable, '-B', '-m', 'venv', '--without-pip', str(source)], check=True)
            python = source / 'bin/python'
            site = Path(subprocess.check_output([str(python), '-B', '-c',
                'import sysconfig;print(sysconfig.get_paths()["purelib"])'], text=True).strip())
            (site / 'release_sentinel.py').write_text('VERSION="selected-venv"\n')
            # Inspect the actual environment query; intercept only the expensive
            # distribution copy after query succeeds. No synthetic query result.
            def copy(src, dest, **kwargs):
                if dest == root / 'private/python':
                    # Model copytree's directory creation so the real no-follow
                    # normalizer validates an actual owned destination.
                    dest.mkdir(parents=True)
                    return
                if dest.name == 'site-packages':
                    self.assertEqual(Path(src), site)
                    raise RuntimeError('verified-source-copy')
            real_run = builder.run
            def run(argv, **kwargs):
                if argv[0] == str(python):
                    return real_run(argv, **kwargs)
                if '-m' in argv:
                    return ''
                return str(root / 'private/venv/site-packages')
            with patch.object(builder.shutil, 'copytree', side_effect=copy), patch.object(builder, 'run', side_effect=run):
                with self.assertRaisesRegex(RuntimeError, 'verified-source-copy'):
                    builder.private_python(python.absolute(), root / 'private')
            self.assertEqual(subprocess.check_output([str(python), '-B', '-c',
                'import release_sentinel;print(release_sentinel.VERSION)'], text=True).strip(), 'selected-venv')


if __name__ == '__main__':
    unittest.main()


class SealGitIndexTests(unittest.TestCase):
    def _git(self, cwd, *args):
        return subprocess.run(['git', *args], cwd=cwd, capture_output=True, text=True)

    def _repo(self, temp):
        repo = Path(temp) / 'repo'
        repo.mkdir()
        self._git(repo, 'init', '-q')
        (repo / 'a.txt').write_text('a\n')
        (repo / 'sub').mkdir()
        (repo / 'sub' / 'b.txt').write_text('b\n')
        self._git(repo, 'add', '.')
        self._git(repo, '-c', 'user.name=t', '-c', 'user.email=t@x.invalid', 'commit', '-qm', 'base')
        return repo

    def _unseal(self, root):
        for directory, dirs, files in __import__('os').walk(root):
            Path(directory).chmod(0o755)
            for name in files:
                (Path(directory) / name).chmod(0o644)

    def test_sealed_checkout_reads_clean_to_diff_index(self):
        """Regression: sealing bumped ctimes after the index was written, so
        `git diff-index --quiet HEAD` flagged every file and version badges
        showed `-dirty` on byte-identical releases."""
        with tempfile.TemporaryDirectory() as temp:
            repo = self._repo(temp)
            __import__('time').sleep(1.1)  # git stat checks are second-granular
            try:
                builder.seal(repo)
                self.assertEqual(self._git(repo, 'diff-index', '--quiet', 'HEAD', '--').returncode, 0)
                self.assertFalse((repo / 'a.txt').stat().st_mode & 0o222)
                self.assertFalse((repo / '.git' / 'index').stat().st_mode & 0o222)
                self.assertFalse(repo.stat().st_mode & 0o222)
            finally:
                self._unseal(repo)

    def test_seal_refuses_checkout_with_tracked_modifications(self):
        with tempfile.TemporaryDirectory() as temp:
            repo = self._repo(temp)
            (repo / 'a.txt').write_text('changed\n')
            try:
                with self.assertRaises(RuntimeError):
                    builder.seal(repo)
            finally:
                self._unseal(repo)

    def test_seal_without_git_dir_still_seals(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / 'plain'
            root.mkdir()
            (root / 'f').write_text('x')
            try:
                builder.seal(root)
                self.assertFalse((root / 'f').stat().st_mode & 0o222)
            finally:
                self._unseal(root)
