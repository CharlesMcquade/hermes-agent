#!/usr/bin/env python3
"""Retire a fully consumed terminal pending-user-restart receipt under the control lock.

A pending-user-restart.json receipt whose recorded transition is COMPLETE
(selected manifest == receipt['new'], durable result terminal, companion
activation transaction terminal) blocks the next pending preparation. This
tool archives the receipt bytes into a timestamped archive directory under
the maintenance base (never deleted) and removes the live file, refusing
closed unless every guard passes. It executes the INSTALLED control modules
(prehashed, exactly like select_for_user_restart.py) — never tooling copies.

Usage:
  python3 -I -B retire_consumed_receipt.py --base <maintenance-dir> \
      --controls <control-refresh-versions-dir> \
      --control-refresh-sha256 <pin> [--approve]

Without --approve it validates everything and prints what it would do.
"""
import argparse
import hashlib
import json
import math
import os
import shutil
import sys
import time
from pathlib import Path

TOOLS = Path(__file__).resolve().parent
sys.path.insert(0, str(TOOLS))

import select_for_user_restart as selector  # noqa: E402


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--base', required=True, type=Path)
    ap.add_argument('--controls', required=True, type=Path)
    ap.add_argument('--control-refresh-sha256', required=True)
    ap.add_argument('--approve', action='store_true')
    ap.add_argument('--restore-transaction', type=Path, default=None,
                    help='Recovery: restore activation-transaction.json from this '
                         'byte-exact archived copy if it is missing, then exit.')
    args = ap.parse_args()

    def require(cond, msg):
        if not cond:
            raise SystemExit(f'REFUSED: {msg}')

    base = args.base.resolve()
    require((base / 'control.lock').exists(), 'control.lock missing')

    observations, _unchanged = selector.prehash_bundle(
        base, args.controls, args.control_refresh_sha256)

    with selector.installed_modules(args.controls, observations) as (controller, watchdog):
        c = controller.Controller(args.base, control_refresh_sha256=args.control_refresh_sha256)
        with c.locked():
            refresh = c.refresh_admission()
            refresh()

            if args.restore_transaction:
                txn_path = base / 'activation-transaction.json'
                require(not txn_path.exists(), 'Transaction file already exists')
                restore_raw = args.restore_transaction.read_bytes()
                import base64 as _b64
                envelope = json.loads(restore_raw)
                payload = json.dumps(envelope['transaction'], sort_keys=True,
                                     separators=(',', ':')).encode()
                require(hashlib.sha256(payload).hexdigest() == envelope['sha256'],
                        'Restored envelope corrupt')
                require(envelope.get('control_refresh_sha256') == args.control_refresh_sha256,
                        'Restored envelope control pin mismatch')
                require(not os.path.lexists(base / watchdog.RECEIPT),
                        'Refusing restore while a pending receipt exists')
                txn_path.write_bytes(restore_raw)
                require(c.retained_file(txn_path)[0] == restore_raw, 'Restore readback mismatch')
                c.read_transaction()
                print('RESTORED transaction from', args.restore_transaction)
                return

            receipt_path = base / watchdog.RECEIPT
            require(os.path.lexists(receipt_path), 'No pending receipt to retire')
            raw = c.retained_file(receipt_path)[0]
            receipt = json.loads(raw)
            require(receipt.get('kind') == 'pending-user-restart', 'Unexpected receipt kind')
            deadline = receipt.get('deadline')
            require(isinstance(deadline, (int, float)) and math.isfinite(deadline),
                    'Receipt deadline missing')

            # 1. The receipt's recorded NEW selection must be the CURRENTLY
            #    selected manifest: this receipt's transition is fully consumed.
            selected = watchdog.record(c, c.manifest_path)
            require(selected['sha256'] == receipt['new']['sha256'],
                    "Selected manifest is not the receipt's new record; transition not consumed")

            # 2. Durable result must be terminal for this receipt's operation.
            result_path = base / watchdog.RESULT
            require(os.path.lexists(result_path), 'Companion result file missing')
            result_raw = c.retained_file(result_path)[0]
            result = json.loads(result_raw)
            require(result.get('operation_id') == receipt.get('operation_id'),
                    'Result operation does not match receipt')
            require(result.get('status') in ('verified', 'rolled_back'),
                    f"Result not terminal: {result.get('status')}")
            completed = result.get('completed_at')
            require(isinstance(completed, (int, float)) and math.isfinite(completed)
                    and completed < deadline + 5, 'Result completion outside receipt deadline')

            # 3. Companion activation transaction must be terminal and unfenced.
            txn = c.read_transaction()
            require(txn is not None and txn.get('phase') in ('verified', 'rolled_back'),
                    'Activation transaction not terminal')
            txn_raw = c.manifest_path.parent.joinpath('activation-transaction.json').read_bytes()
            fence = txn.get('pending_restart_sha256')
            if fence is not None:
                # Same consumed round only: the fence pins this receipt.
                require(fence == sha256(raw),
                        'Activation fence belongs to a different pending round')
                clear_txn = True
            else:
                clear_txn = False

            # 4. Receipt must be expired or consumed long enough ago that no
            #    activation is plausibly in flight (deadline passed).
            require(time.time() > deadline, 'Receipt deadline not yet passed')

            stamp = time.strftime('%Y%m%d-%H%M%S')
            archive_dir = base / f'pending-receipt-archive-{stamp}'
            plan = {
                'archive_dir': str(archive_dir),
                'receipt_sha256': sha256(raw),
                'result_sha256': sha256(result_raw),
                'operation_id': receipt.get('operation_id'),
                'selected_sha256': selected['sha256'],
                'clear_activation_fence': clear_txn,
            }
            print(json.dumps(plan, indent=1))
            if not args.approve:
                print('DRY RUN — rerun with --approve to archive.')
                return

            archive_dir.mkdir(mode=0o700)
            shutil.copy2(receipt_path, archive_dir / watchdog.RECEIPT)
            shutil.copy2(result_path, archive_dir / watchdog.RESULT)
            (archive_dir / 'archive-manifest.json').write_text(json.dumps(
                {**plan, 'archived_at': time.time()}, indent=1) + '\n')
            require(sha256((archive_dir / watchdog.RECEIPT).read_bytes()) == sha256(raw),
                    'Archived receipt bytes differ from live bytes')
            require(sha256((archive_dir / watchdog.RESULT).read_bytes()) == sha256(result_raw),
                    'Archived result bytes differ from live bytes')
            if clear_txn:
                # The transaction FILE must persist (refresh executors require
                # it); only the consumed round's fence key is removed.
                txn.pop('pending_restart_sha256')
                c.save_transaction(txn, txn['phase'])
                require(c.read_transaction() == txn, 'Fence removal readback failed')
            os.remove(receipt_path)
            os.remove(result_path)
            print('RETIRED: receipt+result archived to', archive_dir)


if __name__ == '__main__':
    main()
