"""A watchdog timeout remains failed when the handler projects its diagnostic as text."""
from types import SimpleNamespace
import time

import pytest

from gateway.config import Platform
from gateway.session import SessionSource
from gateway.session_authority import LiveSession, admission_row
from gateway.session_contract import SessionRef
from gateway.session_persistence import authority_persistence
from tests.fixtures.storage_seed import seed_session


@pytest.mark.asyncio
@pytest.mark.parametrize('platform', [Platform.LOCAL, Platform.TELEGRAM])
@pytest.mark.parametrize('late_result', [False, True])
async def test_timeout_diagnostic_keeps_failed_receipt_after_string_projection(owner, platform, late_result):
    from gateway.run import GatewayRunner
    from gateway.run_turn_persistence import GatewayTurnPersistenceMixin
    from gateway.session_ingress import execute_admission
    from gateway.session_results import execution_result, finish_result, admission_result
    from gateway.turn_context import TurnContext
    if platform is Platform.LOCAL:
        from gateway.session_contract import SessionActor
        from gateway.session_local import create_local_session
        # Exercise the real private LOCAL session contract, including its receipt and policy.
        owner.runner.adapters = {}
        owner.runner._evict_cached_agent = lambda route: None
        actor = SessionActor('human', owner.profile_id, frozenset({'session:create', 'session:read'}), 'fixture')
        ref = create_local_session(owner, actor, {
            'request_id': 'timeout', 'source': 'cli', 'cwd': str(owner.persistence.scope.profile_dir),
            'model': 'frozen', 'toolsets': [],
        })
        sid = ref.session_id
    else:
        seed_session(owner.persistence, 's', 'cli')
        sid = 's'
        owner.sessions[sid] = LiveSession(SessionSource(platform, sid, user_id='human'), 'route')
    source = owner.sessions[sid].source
    route = owner.sessions[sid].route
    owner.runner._adapter_for_source = lambda source: None
    owner.runner._agent_activity_summary = lambda agent: {'seconds_since_activity': 1800}
    owner.runner._is_intentional_silence = lambda *args: False
    diagnostic = []

    async def handle(event):
        raw = GatewayRunner._run_agent_timeout_result(owner.runner,
            SimpleNamespace(agent_timeout=1800), TurnContext(session_key=route))
        response, _, _ = await GatewayTurnPersistenceMixin._hmwa_shape_agent_response(
            owner.runner, raw, source, [], SimpleNamespace(session_id=sid), None,
            None, 1, sid, platform.value, time.time())
        diagnostic.append(response)
        if late_result:
            # The abandoned executor shares the capture dict and can return while the handler
            # is still unwinding. Its later value cannot replace the owner's timeout verdict.
            execution_result.get()['result'] = {'final_response': 'late worker answer', 'completed': True}
        return response

    owner.runner._handle_message = handle
    admitted, _created = owner.persistence.admissions.admit(epoch=owner.epoch, principal_id='human',
        session_id=sid, request_id='timeout', payload={'text': 'work'})
    row = admission_row(owner.persistence.admissions.claim(epoch=owner.epoch, session_id=sid))
    response = await execute_admission(owner, SessionRef(owner.profile_id, sid), row)
    finish_result(authority_persistence(owner), epoch=owner.epoch, row=row, response=response, outcome='completed',
                  result=owner.pending_results[admitted.admission_id])
    saved = admission_result(authority_persistence(owner), admitted.admission_id)['result']
    assert owner.persistence.admissions.get(admission_id=admitted.admission_id).outcome == 'failed'
    assert saved['failed'] is True and saved['completed'] is False
    assert saved['final_response'] == response == diagnostic[0]


@pytest.mark.asyncio
async def test_owner_notice_without_execution_is_still_completed(owner):
    from gateway.session_ingress import execute_admission
    from gateway.session_results import finish_result
    seed_session(owner.persistence, 'notice', 'telegram')
    source = SessionSource(Platform.TELEGRAM, 'notice', user_id='human')
    owner.sessions['notice'] = LiveSession(source, 'notice-route')
    owner.runner._adapter_for_source = lambda source: None
    async def notice(event):
        return 'Gateway is paused by the operator.'
    owner.runner._handle_message = notice
    admitted, _created = owner.persistence.admissions.admit(epoch=owner.epoch, principal_id='human',
        session_id='notice', request_id='notice', payload={'text': 'work'})
    row = admission_row(owner.persistence.admissions.claim(epoch=owner.epoch, session_id='notice'))
    response = await execute_admission(owner, SessionRef(owner.profile_id, 'notice'), row)
    finish_result(authority_persistence(owner), epoch=owner.epoch, row=row, response=response, outcome='completed',
                  result=owner.pending_results[admitted.admission_id])
    assert owner.persistence.admissions.get(admission_id=admitted.admission_id).outcome == 'completed'
