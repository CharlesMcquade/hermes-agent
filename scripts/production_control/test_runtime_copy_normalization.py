"""Stdlib-only tests; all filesystem mutations are disposable fixtures."""
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_build


class RuntimeCopyNormalizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ['TMPDIR'])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.copy = self.root / 'copy'
        self.copy.mkdir()

    def test_symlinks_never_mutate_external_targets(self):
        external = self.root / 'external'
        external.write_text('outside')
        external.chmod(0o444)
        if hasattr(os, 'chflags'):
            os.chflags(external, stat.UF_HIDDEN)
            self.addCleanup(os.chflags, external, 0)
        outside_dir = self.root / 'outside-dir'
        outside_dir.mkdir(mode=0o555)
        (self.copy / 'file-link').symlink_to(external)
        (self.copy / 'dir-link').symlink_to(outside_dir, target_is_directory=True)
        (self.copy / 'dangling').symlink_to(self.root / 'absent')
        before = [(p.stat().st_mode, getattr(p.stat(), 'st_flags', 0))
                  for p in (external, outside_dir)]
        release_build.normalize_runtime_copy(self.copy)
        self.assertEqual(before, [(p.stat().st_mode, getattr(p.stat(), 'st_flags', 0))
                                  for p in (external, outside_dir)])
        self.assertTrue((self.copy / 'file-link').is_symlink())


    def test_owned_copy_is_writable_and_flags_clear(self):
        nested = self.copy / 'nested'
        nested.mkdir()
        plain = nested / 'plain'
        plain.write_text('payload')
        executable = nested / 'executable'
        executable.write_text('executable')
        plain.chmod(0o444)
        executable.chmod(0o555)
        (nested / 'internal-link').symlink_to('plain')
        nested.chmod(0o555)
        self.copy.chmod(0o555)
        if hasattr(os, 'chflags'):
            for entry in (plain, executable, nested, self.copy):
                os.chflags(entry, stat.UF_IMMUTABLE)
                self.addCleanup(os.chflags, entry, 0)
        release_build.normalize_runtime_copy(self.copy)
        release_build.normalize_runtime_copy(self.copy)  # rerunnable
        for entry, mode in ((plain, 0o644), (executable, 0o755),
                            (nested, 0o755), (self.copy, 0o755)):
            self.assertEqual(stat.S_IMODE(entry.stat().st_mode), mode)
            self.assertEqual(getattr(entry.stat(), 'st_flags', 0), 0)
        self.assertEqual(plain.read_text(), 'payload')
        self.assertEqual(os.readlink(nested / 'internal-link'), 'plain')

    def test_unsafe_entries_fail_without_mutating_shared_inode(self):
        external = self.root / 'external'
        external.write_text('outside')
        external.chmod(0o444)
        if hasattr(os, 'chflags'):
            os.chflags(external, stat.UF_HIDDEN)
            self.addCleanup(os.chflags, external, 0)
        before = external.stat()
        link = self.copy / 'hardlink'
        os.link(external, link)
        with self.assertRaisesRegex(RuntimeError, 'Hardlinked'):
            release_build.normalize_runtime_copy(self.copy)
        self.assertEqual(external.stat().st_mode, before.st_mode)
        self.assertEqual(getattr(external.stat(), 'st_flags', 0),
                         getattr(before, 'st_flags', 0))
        link.unlink()
        fifo = self.copy / 'fifo'
        os.mkfifo(fifo)
        with self.assertRaisesRegex(RuntimeError, 'Unsupported'):
            release_build.normalize_runtime_copy(self.copy)
        fifo.unlink()
        self.copy.chmod(0o777)
        with self.assertRaisesRegex(RuntimeError, 'exclusively owned'):
            release_build.normalize_runtime_copy(self.copy)

    def test_root_and_ancestor_symlinks_fail_closed(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.copy, target_is_directory=True)
        nested = self.copy / 'nested'
        nested.mkdir(mode=0o555)
        self.copy.chmod(0o555)
        for path in (alias, alias / 'nested'):
            with self.assertRaises(OSError):
                release_build.normalize_runtime_copy(path)
        self.assertEqual(stat.S_IMODE(self.copy.stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE(nested.stat().st_mode), 0o555)

    def test_directory_swap_to_symlink_is_not_followed(self):
        nested = self.copy / 'nested'
        nested.mkdir()
        external = self.root / 'external'
        external.mkdir(mode=0o555)
        real_open = os.open

        def swap(name, flags, **kwargs):
            if name == 'nested':
                nested.rename(self.copy / 'saved')
                nested.symlink_to(external, target_is_directory=True)
            return real_open(name, flags, **kwargs)

        with mock.patch.object(release_build.os, 'open', side_effect=swap):
            with self.assertRaises(OSError):
                release_build.normalize_runtime_copy(self.copy)
        self.assertEqual(stat.S_IMODE(external.stat().st_mode), 0o555)

    def test_normalization_errors_propagate(self):
        for target in ('os.fchmod', 'os.listdir', '_clear_runtime_flags'):
            with self.subTest(target=target):
                with mock.patch('release_build.' + target,
                                side_effect=PermissionError('fixture denial')):
                    with self.assertRaisesRegex(PermissionError, 'fixture denial'):
                        release_build.normalize_runtime_copy(self.copy)


class ProbeDiagnosticsTests(unittest.TestCase):
    def test_failed_probe_does_not_write_or_report_candidate_output(self):
        import subprocess
        import release_workflow as workflow
        with tempfile.TemporaryDirectory(dir=os.environ['TMPDIR']) as temp:
            home = Path(temp)
            result = subprocess.CompletedProcess([], 1, 'private stdout', 'private stderr')
            with mock.patch.object(workflow.subprocess, 'run', return_value=result), \
                 mock.patch.object(workflow.canary, 'sandbox_policy', return_value=''), \
                 mock.patch('builtins.open', side_effect=AssertionError('unexpected log write')):
                with self.assertRaisesRegex(RuntimeError, '^Contained interpreter probe failed$'):
                    workflow.contained_command([sys.executable], home, [])
            self.assertEqual([p.name for p in home.iterdir()], ['probe.sb'])

    def test_identity_mismatch_does_not_report_candidate_output(self):
        import json
        import release_workflow as workflow
        manifest = {'services': {'agent': {'repo': '/fixture', 'commit': 'a' * 40,
                                           'runtimes': [], 'argv': [sys.executable]}}}
        payload = json.dumps({'fingerprint': 'git:HEAD:' + 'a' * 40,
                              'runtime': 'private candidate data',
                              'reported': {'sha': 'private candidate data'}})
        with mock.patch.object(workflow, 'contained_command', return_value=payload):
            with self.assertRaisesRegex(RuntimeError, '^Actual gateway code SHA differs from manifest$'):
                workflow.runtime_identity(manifest, os.environ['TMPDIR'])


if __name__ == '__main__':
    unittest.main()
