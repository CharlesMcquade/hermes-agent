"""Finite build-time continuation configuration and routing override fences."""
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_workflow as workflow
import select_for_user_restart as selector


class ContinuationBuildConfigTests(unittest.TestCase):
    def test_disabled_is_unchanged(self):
        self.assertEqual(workflow.continuation_environment({}), {})

    def test_exact_finite_environment(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as temp:
            root = Path(temp).resolve()
            cfg = {'continuation_dir': str(root / 'operation' / 'continuation'),
                   'output': str(root / 'release'), 'agent_repo': str(root / 'agent'),
                   'webui_repo': str(root / 'webui'), 'scratch': str(root / 'scratch'),
                   'controls': str(root / 'controls')}
            result = workflow.continuation_environment(cfg)
            self.assertEqual(result, {'HERMES_WEBUI_CONTINUATION_DIR': cfg['continuation_dir'],
                                     'HERMES_WEBUI_RUNTIME_ADAPTER': 'legacy-direct',
                                     'HERMES_WEBUI_CHAT_BACKEND': 'legacy'})
            self.assertTrue(set(result).issubset(selector.ROUTING_KEYS))

    def test_overlap_and_alias_rejected(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as temp:
            root = Path(temp).resolve()
            protected = root / 'release'; protected.mkdir()
            for directory in (protected, protected / 'subdir', root):
                with self.subTest(directory=directory), self.assertRaises(RuntimeError):
                    workflow.continuation_environment({'continuation_dir': str(directory),
                                                       'output': str(protected)})
            (root / 'alias').symlink_to(protected, target_is_directory=True)
            with self.assertRaises(RuntimeError):
                workflow.continuation_environment({'continuation_dir': str(root / 'alias' / 'subdir')})

    def test_relative_path_rejected(self):
        with self.assertRaises(RuntimeError):
            workflow.continuation_environment({'continuation_dir': 'relative/continuation'})


if __name__ == '__main__':
    unittest.main()
