# Upgrade already-native management controls without restarting

`upgrade_native_controls.py` is a separate post-native path, not the original
legacy installer and not a repair that blesses observed drift. It requires a
currently admitted management bundle and terminal activation transaction.

## Boundaries

- It never starts/stops/signals a service or invokes launchctl.
- It never changes the signed app, stable launcher, service plists, selected
  application manifest, credentials, or live application files.
- It plans six control modules from genuine objects in an exact Git commit;
  uncommitted worktree edits and Git replacement refs are irrelevant. Git reads
  disable replacements and inherited Git routing/config environment. Three
  generated management wrappers carry the new receipt pin; their original
  modes/owner are preserved. Before importing management code, the installer
  independently checks every bundle byte against the pinned receipt.
- Both current and replacement admission run in separate `-I -B` subprocesses,
  with a minimal environment. They import management code, not application code.
- Shared flock, whole-baseline checks, and immutable plan pin guard publication.
  The final receipt is published last. Intermediate wrapper/receipt mismatches
  fail closed; no unauthenticated permissive bridge is used.
- Exceptions restore exact known old bytes. Abrupt process exit leaves the
  immutable plan and backups for explicit `recover`. Recovery checks every
  target before restoring any and revalidates all observed targets and guards
  before every restore edge. Unknown concurrent writes fail closed without
  overwriting the intervening writer.
- This does not promise uninterrupted management admission during a process
  crash. The serving application remains untouched; a failed upgrade may require
  recovery before management becomes usable again.

## Commands

Use a nonproduction Python. Never use a release interpreter without bytecode
suppression, and never run tests in a release source directory.

```
PYTHONDONTWRITEBYTECODE=1 <python> -B upgrade_native_controls.py plan \
  --base <maintenance> --repo <source-repo> --commit <full-commit> \
  --version-name <fresh-name> --output <new-private-plan-directory> \
  --current-pin <currently-trusted-refresh-receipt-sha256>

PYTHONDONTWRITEBYTECODE=1 <python> -B upgrade_native_controls.py apply \
  --plan <plan.json> --plan-sha256 <reviewed-plan-pin> --approve

# Only to restore known bytes from this operation:
PYTHONDONTWRITEBYTECODE=1 <python> -B upgrade_native_controls.py recover \
  --plan <plan.json> --plan-sha256 <same-pin> --approve
```

Do not infer authorization by hashing arbitrary drift and passing the hash.
Admission must start at the currently trusted receipt/wrappers. Keep plans private
because backups contain local paths and installation data.

## Plan size contract

Individual source, target and guard files remain bounded at 64 MiB. The serialized
JSON plan has a separate 256 MiB limit to accommodate base64-embedded old/new
receipts, journals, transactions and guard backups. This is a supported bounded
aggregate, not an increase to the per-file limit. Larger installations must stop
and review the format; there is no automatic cap override or blob-store fallback.

Generation validates the serialized size and every embedded old/new/guard record
before publishing `plan.json`. A refused plan can leave its private source staging
directory, but never a published oversized plan or installed-target writes. Atomic
writes reject oversized records before creating a temporary file. Import uses the
same aggregate cap, explicit SHA pin, and per-record checks before apply/recover
can import management code or write any target. No-follow, ownership/mode and
mid-read mutation checks apply unchanged to both file classes. The plan remains
private and immutable; recovery retains the existing known-byte CAS checks.

## Verification contract

The test suite uses real isolated Git repositories and real helper subprocesses
with a small independent admission fixture, plus the real native refresh load()
composed against disposable native-host fixtures. It tests modes, exact old/new
bytes, secret-env exclusion, source tampering, genuine commit type/replacement
refs, import-before-verification refusal, lock contention, symlinks, selector
drift, unknown writers between recovery edges, exceptions and abrupt exit after
every managed publication edge. These are not proof of the real native host.

Run only the scoped stdlib suite (no application imports or live supervision):

```sh
PYTHONDONTWRITEBYTECODE=1 TMPDIR=<private-scratch> <nonproduction-python> -B \
  -m unittest discover -s scripts/production_control -p 'test_upgrade_native_controls*.py' -v
```

Before real installation: independently review source, verify current admission,
record current selector/plists/launcher, host and child identities, then make a
pinned plan. After installation: reread the exact targets, verify installed
admission, untouched app/launcher/selector/plists, and unchanged live identities.
Keep application selection and the human restart as separate gates.

Status: development tooling. No production installation has been performed by
these tests. A successful controls installation is not application readiness.
