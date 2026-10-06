"""Exercise the actual native refresh admission, using disposable native fixtures."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

import test_control_refresh_runtime as fixtures
import upgrade_native_controls as u


class NativeUpgradeCompositionTests(unittest.TestCase):
    def setUp(self):
        self.f=fixtures.RefreshRuntimeTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.base=self.f.base.resolve()
        # Existing fixture uses literal 'home' to model identity; helper reads
        # actual fixture HOME, not the real account.
        self.assertEqual(Path.home(),self.f.home)
        body=dict(schema_version=1,kind='native-control-refresh',receipt=self.f.receipt,
                  phase='committed',stage_sha256=self.f.receipt['stage_sha256'],return_proof=None)
        u.atomic(self.base/u.JOURNAL,u.packed(u.encoded(dict(payload=body,sha256=u.sha(u.encoded(body))))))
        self.repo=self.base/'source-repo'; self.repo.mkdir(mode=0o700)
        src=self.repo/'scripts/production_control';src.mkdir(parents=True)
        for n in u.FILES:
            (src/n).write_bytes((Path(u.__file__).parent/n).read_bytes())
        def git(*args):
            return subprocess.check_output(['git','-C',str(self.repo),*args],stderr=subprocess.DEVNULL,text=True)
        git('init','-q');git('add','.')
        git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','source')
        self.commit=git('rev-parse','HEAD').strip()
        self.before={n:u.record(self.base/n) for n in u.TARGETS}
        self.protected=dict(self.f.protected)
        self.calls=list(self.f.host.calls)

    def tearDown(self):
        for root,dirs,_ in os.walk(self.base):
            Path(root).chmod(0o700)

    def test_plan_apply_real_load_and_recover_real_load(self):
        u.admit(self.base,self.f.pin,self.f.version)
        plan=u.build_plan(self.base,self.repo,self.commit,'v3',self.base/'upgrade-plan',self.f.pin)
        self.assertEqual(self.before,{n:u.record(self.base/n) for n in u.TARGETS})
        result=u.apply_plan(Path(plan['plan']),plan['plan_sha256'],approval=True)
        self.assertEqual(result['status'],'installed_controls_no_restart')
        u.admit(self.base,result['new_pin'],Path(result['version']))
        result=u.apply_plan(Path(plan['plan']),plan['plan_sha256'],recover=True,approval=True)
        self.assertEqual(result['status'],'restored_controls_no_restart')
        self.assertEqual(self.before,{n:u.record(self.base/n) for n in u.TARGETS})
        u.admit(self.base,self.f.pin,self.f.version)
        self.assertEqual(self.calls,self.f.host.calls)
        for p,expected in self.protected.items():
            self.assertEqual((p.read_bytes(),p.stat().st_ino,p.stat().st_mode),expected)

    def test_real_admission_rejects_root_receipt_drift_before_plan(self):
        path=self.base/'native-install-receipt.json'
        original=u.record(path)
        u.atomic(path,u.packed(b'{}',original['mode']))
        with self.assertRaisesRegex(ValueError,'admission'):
            u.build_plan(self.base,self.repo,self.commit,'v3',self.base/'upgrade-plan',self.f.pin)
        self.assertEqual(self.before,{n:u.record(self.base/n) for n in u.TARGETS})
        self.assertEqual(self.calls,self.f.host.calls)


if __name__=='__main__':
    unittest.main()
