"""Sandbox-only publisher driver for test_continuation_process.py."""
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import continuation_publish as pub

root, webui, action = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
manifest = json.loads((root / 'manifest.json').read_text())
consumer = pub.load_consumer(manifest)
private = root / 'private'
deployment = pub.deployment_binding(manifest)
if action == 'initialize':
    pub.initialize(consumer, private, deployment)
elif action == 'request':
    sid = sys.argv[4]
    anchor = pub.human_anchor(root / 'state', sid)
    binding = pub.capture_settled(consumer, session_id=sid, profile='default',
        workspace=str(root / 'home'), session_dir=root / 'webui/sessions',
        state_home=root / 'state', expected_anchor=anchor,
        health=lambda: json.loads((root / 'health.json').read_text()), timeout=5)
    pub.publish_request(consumer, private, admission_id='a' * 32,
        controller_operation_id='isolated-process-rehearsal', deployment=deployment,
        binding=binding, message='CONTINUATION_PROCESS_MARKER')
elif action == 'terminal':
    # This proves application composition, NOT installed controller admission.
    health = json.loads((root / 'health.json').read_text())
    request = json.loads((private / 'request.json').read_text())
    proof = {'health': 'ok', 'deep_health': 'ok',
             'process_identity': {'webui': {'child': {'pid': int(sys.argv[4])}}}}
    pub.publish_terminal(consumer, private, request, proof, health)
else:
    raise ValueError(action)
