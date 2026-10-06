"""Disposable subprocess tests. No installed controls, launchctl or app imports."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import upgrade_native_controls as u

# Independent fixture authority exercises real helper subprocesses; it is NOT a
# substitute for a final read-only admission against installed native controls.
AUTHORITY = '''import hashlib,json,os
from pathlib import Path
FILES=('restart_production.py','watchdog.py','approved_restart_job.py')
def new_wrappers(base,version,pin):
    return {n: '# fixture wrapper '+str(version)+' '+pin+' '+n+'\\n' for n in FILES}
def load(base,pin,executor):
    assert 'FAKE_PROVIDER_SECRET' not in os.environ
    raw=(base/'native-control-refresh-receipt.json').read_bytes()
    assert hashlib.sha256(raw).hexdigest()==pin
    r=json.loads(raw)
    assert str(executor.parent)==r['stage']['version']
    for n,text in new_wrappers(base,executor.parent,pin).items():
        assert (base/n).read_text()==text
    t=json.loads((base/'activation-transaction.json').read_text())
    assert t['control_refresh_sha256']==pin
    for n,h in r['stage']['control_sha256'].items():
        assert hashlib.sha256((executor.parent/n).read_bytes()).hexdigest()==h
    return r,{},lambda:None
'''


class UpgradeTests(unittest.TestCase):
    def setUp(self):
        scratch = os.environ.get('TMPDIR')
        self.tmp = tempfile.TemporaryDirectory(dir=scratch, prefix='control-upgrade-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.base = self.root/'maintenance'
        self.repo = self.root/'repo'
        self.base.mkdir(mode=0o700)
        self.repo.mkdir(mode=0o700)
        self.old_version = self.base/'control-refresh-versions'/'old'
        self.old_version.mkdir(parents=True, mode=0o700)
        for n in u.FILES:
            (self.old_version/n).write_text(AUTHORITY if n=='control_refresh.py' else '# old fixture\n')
        hashes = {n:u.sha((self.old_version/n).read_bytes()) for n in u.FILES}
        receipt = dict(stage=dict(version=str(self.old_version),control_sha256=hashes))
        self.pin = u.sha(u.encoded(receipt))
        u.atomic(self.base/u.RECEIPT,u.packed(u.encoded(receipt)))
        u.atomic(self.base/u.JOURNAL,u.packed(b'{}\n'))
        txn = dict(phase='verified',operation_id='fixture')
        env = dict(schema_version=2,transaction=txn,control_refresh_sha256=self.pin,
                   sha256=u.sha(json.dumps(txn,sort_keys=True,separators=(',',':')).encode()))
        u.atomic(self.base/u.TRANSACTION,u.packed(u.encoded(env),0o600))
        for n,text in u.wrappers(self.base,self.pin,self.old_version,self.old_version).items():
            u.atomic(self.base/n,u.packed(text.encode(),0o600 if n=='watchdog.py' else 0o644))
        u.atomic(self.base/'control.lock',u.packed(b'',0o600))
        manifest = dict(services={s:dict(plist_path=str(self.root/(s+'.plist'))) for s in ('agent','webui')})
        for s in ('agent','webui'):
            u.atomic(self.root/(s+'.plist'),u.packed((s+' plist').encode(),0o600))
        u.atomic(self.base/'production-release.json',u.packed(u.encoded(manifest),0o600))
        u.atomic(self.base/'production_launcher.py',u.packed(b'# signed stable launcher\n',0o644))
        source = self.repo/'scripts/production_control'
        source.mkdir(parents=True)
        for n in u.FILES:
            (source/n).write_text(AUTHORITY if n=='control_refresh.py' else '# new fixture\n')
        self.git('init','-q')
        self.git('add','.')
        self.git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','fixture')
        self.commit = self.git('rev-parse','HEAD').strip()
        u.atomic(self.old_version/'control-receipt.json',u.packed(u.encoded(hashes)))
        for path in self.old_version.iterdir():
            path.chmod(0o444)
        self.old_version.chmod(0o555)
        self.before = {n:u.record(self.base/n) for n in u.TARGETS}
        self.unchanged = u.guards(self.base)

    def tearDown(self):
        # TemporaryDirectory must be able to remove sealed fixture bundle dirs.
        for root, dirs, _ in os.walk(self.root):
            Path(root).chmod(0o700)

    def git(self,*args):
        return subprocess.check_output(['git','-C',str(self.repo),*args],text=True,stderr=subprocess.DEVNULL)

    def plan(self):
        p=u.build_plan(self.base,self.repo,self.commit,'new',self.root/'plan',self.pin)
        self.plan_path=Path(p['plan']); self.plan_pin=p['plan_sha256']
        return p

    def unchanged_before(self):
        self.assertEqual(self.before,{n:u.record(self.base/n) for n in u.TARGETS})
        u.check_guards(self.unchanged)

    def test_plan_only_preserves_production_bytes(self):
        p=self.plan(); self.unchanged_before()
        self.assertEqual(p['status'],'planned_not_installed')
        self.assertFalse((self.base/'control-refresh-versions/new').exists())

    def test_apply_real_admission_preserves_modes_and_untouched_state(self):
        p=self.plan()
        with patch.dict(os.environ,{'FAKE_PROVIDER_SECRET':'must-not-leak'}):
            result=u.apply_plan(self.plan_path,self.plan_pin,approval=True)
        self.assertEqual(result['status'],'installed_controls_no_restart')
        u.admit(self.base,p['new_pin'],Path(result['version']))
        u.check_guards(self.unchanged)
        self.assertEqual(u.record(self.base/'watchdog.py')['mode'],0o600)
        self.assertEqual(u.record(self.base/'restart_production.py')['mode'],0o644)

    def test_explicit_approval_required(self):
        self.plan()
        with self.assertRaisesRegex(ValueError,'approve'):
            u.apply_plan(self.plan_path,self.plan_pin)
        self.unchanged_before()

    def test_wrong_pin_rejected(self):
        self.plan()
        with self.assertRaisesRegex(ValueError,'pin mismatch'):
            u.apply_plan(self.plan_path,'0'*64,approval=True)
        self.unchanged_before()

    def test_modified_source_worktree_not_used(self):
        (self.repo/'scripts/production_control/watchdog.py').write_text('raise Exception("uncommitted")')
        self.plan()
        self.assertEqual((self.plan_path.parent/'controls/watchdog.py').read_text(),'# new fixture\n')

    def test_git_replacements_cannot_change_claimed_source(self):
        original=self.git('--no-replace-objects','show',self.commit+':scripts/production_control/watchdog.py')
        (self.repo/'scripts/production_control/watchdog.py').write_text('# replacement object\n')
        self.git('add','.')
        self.git('-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','-qm','replacement')
        self.git('replace',self.commit,self.git('rev-parse','HEAD').strip())
        result=self.plan()
        self.assertEqual(result['source_commit'],self.commit)
        self.assertEqual((self.plan_path.parent/'controls/watchdog.py').read_text(),original)
        self.unchanged_before()

    def test_management_hashes_checked_before_any_import(self):
        source=self.old_version/'control_refresh.py'; source.chmod(0o600)
        source.write_text('from pathlib import Path\n'
                          'def load(base,*args):\n (base/"unexpected-import").write_text("ran")\n')
        source.chmod(0o444)
        with self.assertRaisesRegex(ValueError,'Staged control changed'):
            self.plan()
        self.assertFalse((self.base/'unexpected-import').exists())
        self.unchanged_before()

    def test_recovery_checks_unknown_writer_between_every_edge(self):
        self.plan(); plan=json.loads(self.plan_path.read_text()); real=u.atomic
        for target in ('watchdog.py',u.TRANSACTION):
            with self.subTest(target=target):
                for name in u.TARGETS:
                    real(self.base/name,plan['new'][name])
                injected=[]; calls=[]
                def write(path,rec):
                    calls.append(path.name); real(path,rec)
                    if path==self.base/u.TRANSACTION and not injected:
                        injected.append(True)
                        real(self.base/target,u.packed(b'# unrelated concurrent writer',0o600))
                with patch.object(u,'atomic',write),self.assertRaisesRegex(ValueError,'Concurrent recovery drift'):
                    u.apply_plan(self.plan_path,self.plan_pin,recover=True,approval=True)
                self.assertEqual(calls,[u.TRANSACTION])
                self.assertEqual((self.base/target).read_bytes(),b'# unrelated concurrent writer')
                self.assertFalse((self.plan_path.parent/'result.json').exists())

    def test_stage_bundle_tamper_refused(self):
        self.plan(); path=self.plan_path.parent/'controls/watchdog.py'
        path.chmod(0o600); path.write_text('# evil')
        with self.assertRaises(ValueError):
            u.apply_plan(self.plan_path,self.plan_pin,approval=True)
        self.unchanged_before()

    def test_source_must_be_commit_object(self):
        tree=self.git('rev-parse','HEAD^{tree}').strip()
        with self.assertRaisesRegex(ValueError,'genuine commit'):
            u.build_plan(self.base,self.repo,tree,'new',self.root/'plan',self.pin)
        self.unchanged_before()

    def test_selector_change_refuses_before_publication(self):
        self.plan(); path=self.base/'production-release.json'
        u.atomic(path,u.packed(b'{"unexpected":true}',0o600))
        with self.assertRaisesRegex(ValueError,'Untouched selector'):
            u.apply_plan(self.plan_path,self.plan_pin,approval=True)
        self.assertEqual(path.read_bytes(),b'{"unexpected":true}')
        self.assertEqual(self.before,{n:u.record(self.base/n) for n in u.TARGETS})

    def test_exception_each_publication_edge_restores_old(self):
        self.plan(); real=u.atomic
        for target in u.TARGETS:
            with self.subTest(target=target):
                bundle=self.base/'control-refresh-versions/new'
                if bundle.exists():
                    import shutil
                    bundle.chmod(0o700); shutil.rmtree(bundle)
                fired=[]
                def fail(path,rec):
                    real(path,rec)
                    if path == self.base/target and not fired:
                        fired.append(True)
                        raise RuntimeError('fixture crash edge')
                with patch.object(u,'atomic',fail),self.assertRaisesRegex(RuntimeError,'crash edge'):
                    u.apply_plan(self.plan_path,self.plan_pin,approval=True)
                self.unchanged_before()

    def test_abrupt_exit_each_edge_recovered_by_fresh_process(self):
        self.plan()
        code='''import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import upgrade_native_controls as u
real=u.atomic
def crash(p,r):
    real(p,r)
    if str(p)==sys.argv[4]: os._exit(91)
u.atomic=crash
u.apply_plan(Path(sys.argv[2]),sys.argv[3],approval=True)
'''
        for n in u.TARGETS:
            with self.subTest(target=n):
                target=self.base/'control-refresh-versions/new'
                if target.exists():
                    import shutil
                    target.chmod(0o700); shutil.rmtree(target)
                proc=subprocess.run([sys.executable,'-I','-B','-c',code,str(Path(u.__file__).parent),
                                     str(self.plan_path),self.plan_pin,str(self.base/n)],capture_output=True)
                self.assertEqual(proc.returncode,91,proc.stderr.decode())
                result=u.apply_plan(self.plan_path,self.plan_pin,recover=True,approval=True)
                self.assertEqual(result['status'],'restored_controls_no_restart')
                self.unchanged_before()

    def test_recovery_refuses_unknown_writer_without_partial_restore(self):
        self.plan(); plan=json.loads(self.plan_path.read_text())
        u.atomic(self.base/u.TRANSACTION,plan['new'][u.TRANSACTION])
        u.atomic(self.base/'watchdog.py',u.packed(b'# unrelated writer',0o600))
        partial={n:u.record(self.base/n) for n in u.TARGETS}
        with self.assertRaisesRegex(ValueError,'Unknown publication drift'):
            u.apply_plan(self.plan_path,self.plan_pin,recover=True,approval=True)
        self.assertEqual(partial,{n:u.record(self.base/n) for n in u.TARGETS})

    def test_existing_version_never_reused(self):
        self.plan(); u.apply_plan(self.plan_path,self.plan_pin,approval=True)
        u.apply_plan(self.plan_path,self.plan_pin,recover=True,approval=True)
        with self.assertRaisesRegex(ValueError,'Version exists'):
            u.apply_plan(self.plan_path,self.plan_pin,approval=True)
        self.unchanged_before()

    def test_symlink_target_refused(self):
        self.plan(); path=self.base/'watchdog.py'; raw=path.read_bytes()
        path.unlink(); other=self.root/'other';other.write_bytes(raw);path.symlink_to(other)
        with self.assertRaises(OSError):
            u.apply_plan(self.plan_path,self.plan_pin,approval=True)
        self.assertEqual(other.read_bytes(),raw)

    def test_lock_contention_refuses_without_mutation(self):
        self.plan()
        with u.locked(self.base),self.assertRaises(BlockingIOError):
            u.apply_plan(self.plan_path,self.plan_pin,approval=True)
        self.unchanged_before()


if __name__=='__main__':
    unittest.main()
