"""Completion controls: current release session/callback/worker to encrypted edge."""
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from gateway.platforms.base import MessageEvent, MessageType
from gateway.run_turn_runner import TurnRunner
from tests.gateway.test_buzz_lifecycle_release import Capture, local_runner, source
from tests.gateway.test_buzz_activity_release import (
    _make_adapter, _FakeWebSocket, nostr_auth, decrypt_owner,
)


@pytest.mark.asyncio
@pytest.mark.parametrize('fresh', [False, True])
async def test_session_open_authority_reaches_current_worker_with_empty_history(monkeypatch, fresh):
    import gateway.run_turn as turn_module
    route = Capture()
    runner, _ = local_runner(route)
    src = source()
    entry = SimpleNamespace(created_at=1, updated_at=2, is_fresh_reset=fresh,
                            session_id='session-1', session_key='key')
    runner.hooks = SimpleNamespace(emit=AsyncMock())
    runner.config = SimpleNamespace()
    monkeypatch.setattr(turn_module, 'build_session_context', lambda *args: {})
    runner._set_session_env = lambda context: {}
    runner._clear_session_env = lambda tokens: None
    runner._pinned_session_context_prompt = lambda *args: ''
    runner._voice_channel_sidecar_note = lambda *args: None
    runner._bind_adapter_run_generation = lambda *args: None
    runner._hmwa_apply_message_timestamp = lambda event, text: (text, text, None)
    runner.session_store = object()
    runner._async_session_store = SimpleNamespace(_store=runner.session_store, load_transcript=AsyncMock(return_value=[]))
    runner._hmwa_run_session_hygiene = AsyncMock(return_value=[])
    for name in ('_hmwa_acquire_turn_lease', '_mark_durable_active_turn', '_hmwa_first_contact_notes'):
        setattr(runner, name, AsyncMock())
    runner._prepare_profile_scoped_inbound_message_text = AsyncMock(return_value='private-input')
    event = MessageEvent(text='private-input', source=src, message_id='a'*64,
                         message_type=MessageType.TEXT)
    prepared, tokens = await runner._hmwa_prepare_turn(event, src, entry, 'key', 'key', 1)
    assert entry.is_fresh_reset is False
    assert runner.hooks.emit.await_count == int(fresh)
    runner._hmwa_resolve_session = AsyncMock(return_value=(src, entry, 'key'))
    runner._hmwa_prepare_turn = AsyncMock(return_value=(prepared, tokens))
    # Stop at the delivery boundary, after the real worker and terminal latch.
    runner._hmwa_stop_typing_for_turn = AsyncMock(side_effect=asyncio.CancelledError)
    runner._hmwa_agent_error_reply = AsyncMock(side_effect=AssertionError('unexpected pre-delivery error'))
    with pytest.raises(asyncio.CancelledError):
        await runner._handle_message_with_agent(event, src, 'key', 1)
    assert [e.is_new_session for e in route.events if e.phase == 'session_resolved'] == [fresh]
    assert [e.outcome for e in route.events if e.phase == 'turn_finished'] == ['success']


def wire_current_agent(turn, agent, native_calls):
    """Use actual per-turn rewire on the same cached agent; stub unrelated UI lanes."""
    ctx = turn._ctx
    for name in ('progress_callback', 'voice_ack_callback', '_step_callback_sync',
                 '_status_callback_sync', '_event_callback_sync', '_status_adapter',
                 'process_task_id', 'process_baseline'):
        setattr(ctx, name, None)
    ctx._native_slack_task_cards = True
    ctx.native_tool_start_callback = lambda *args: native_calls.append('start')
    ctx.native_tool_complete_callback = lambda *args: native_calls.append('finish')
    ctx._hooks_ref = SimpleNamespace(loaded_hooks=[])
    ctx.user_config = {'display': None}
    ctx._thinking_enabled = False
    ctx.tools_holder = [None]
    turn._runner._service_tier = None
    turn._runner._consume_pending_turn_sidecar_notes = lambda key: []
    turn._make_bg_review_callbacks = lambda: (lambda message: None, lambda: None)
    turn._attach_session_title_callback = lambda *args: None
    turn._wire_turn_agent_callbacks(agent, {}, None, None, None, False)
    assert ctx.agent_holder[0] is agent
    assert agent.memory_notifications == 'on'


@pytest.mark.asyncio
@pytest.mark.parametrize('outcome', ['success', 'failed', 'cancelled', 'exception'])
async def test_current_worker_reused_agent_to_owner_encrypted_terminal(outcome):
    owner = '02'.zfill(64)
    adapter = _make_adapter({'activity_owner_pubkey': nostr_auth.public_key_hex(owner)})
    ws = _FakeWebSocket()
    adapter._ws_active = True
    adapter._ws_connection = ws
    runner, contexts = local_runner(adapter)
    agent = SimpleNamespace()
    native_calls = []

    def start(ctx, callback):
        async def model():
            wire_current_agent(callback.__self__, agent, native_calls)
            agent.tool_start_callback('private-call-id', 'terminal', {'secret': 'private-args'})
            agent.tool_complete_callback('private-call-id', 'terminal', {}, 'private-result')
            if len(contexts) == 2:
                if outcome == 'cancelled':
                    raise asyncio.CancelledError
                if outcome == 'exception':
                    raise RuntimeError('private-error')
            result = {'final_response': '', 'messages': [], 'completed': True,
                      'failed': len(contexts) == 2 and outcome == 'failed',
                      'media_urls': ['synthetic-media']}
            ctx.result_holder[0] = result
            return result
        return SimpleNamespace(executor_task=asyncio.create_task(model()), agent_timeout=None)

    runner._run_agent_start_turn_worker = start
    try:
        result = await runner._run_agent('private-input', '', [], source(), 'session-1',
                                        session_key='key', is_new_session=True)
        assert result['media_urls'] == ['synthetic-media']
        if outcome in {'cancelled', 'exception'}:
            with pytest.raises(asyncio.CancelledError if outcome == 'cancelled' else RuntimeError):
                await runner._run_agent('private-input', '', [], source(), 'session-1', session_key='key')
        else:
            result = await runner._run_agent('private-input', '', [], source(), 'session-1', session_key='key')
            assert result['media_urls'] == ['synthetic-media']
        await asyncio.wait_for(adapter._activity_queue.join(), 2)
        frames = [decrypt_owner(frame[1], owner) for frame in ws.sent]
        for frame in ws.sent:
            event = frame[1]
            assert event['kind'] == 24200
            assert nostr_auth.schnorr_verify(bytes.fromhex(event['id']), adapter._self_pubkey, event['sig'])
            assert event['tags'] == [['p', nostr_auth.public_key_hex(owner)],
                                     ['agent', adapter._self_pubkey], ['frame', 'telemetry']]
            with pytest.raises(AssertionError):
                decrypt_owner(event, '05'.zfill(64))
            assert adapter._handle_activity_ack(['OK', event['id'], True, 'stored'])
        turns = list(dict.fromkeys(frame['turnId'] for frame in frames))
        assert len(turns) == 2
        for index, turn_id in enumerate(turns):
            turn_frames = [frame for frame in frames if frame['turnId'] == turn_id]
            terminal = 'turn_completed' if index == 0 or outcome == 'success' else 'turn_error'
            assert [frame['kind'] for frame in turn_frames] == [
                'turn_started', 'session_resolved', 'acp_read', 'acp_read', terminal]
            assert all(frame['channelId'] == source().chat_id and frame['sessionId'] == 'session-1'
                       for frame in turn_frames)
            assert turn_frames[1]['payload']['isNewSession'] is (index == 0)
            if terminal == 'turn_error':
                assert turn_frames[-1]['payload']['status'] == ('failed' if outcome == 'exception' else outcome)
        assert native_calls == ['start', 'finish', 'start', 'finish']
        assert not adapter._activity_pending_event_ids
        assert not adapter._activity_terminal_replay
        assert 'private-' not in repr(frames)
    finally:
        adapter._ws_active = False
        await adapter._reset_activity_transport()


@pytest.mark.asyncio
async def test_cancelled_reset_drains_saturated_queue_and_retains_terminals():
    owner = '02'.zfill(64)
    adapter = _make_adapter({'activity_owner_pubkey': nostr_auth.public_key_hex(owner)})
    entered = asyncio.Event()

    class HeldSocket:
        async def send(self, raw):
            entered.set()
            await asyncio.Event().wait()

    adapter._activity_queue = asyncio.Queue(maxsize=1)
    adapter._ws_connection = HeldSocket()
    adapter._ws_active = True
    adapter._enqueue_activity('turn_completed', channel_id='channel-1', session_id='s', turn_id='first')
    await asyncio.wait_for(entered.wait(), 2)
    timers = [timer for _, timer in adapter._activity_pending_event_ids.values()]
    assert adapter._enqueue_activity('turn_liveness', channel_id='channel-1', session_id='s', turn_id='active')
    assert not adapter._enqueue_activity('turn_liveness', channel_id='channel-1', session_id='s', turn_id='drop')
    assert adapter._enqueue_activity('turn_error', channel_id='channel-1', session_id='s', turn_id='second')
    adapter._ws_active = False
    reset = asyncio.create_task(adapter._reset_activity_transport())
    await asyncio.sleep(0)  # reset is now awaiting the held sender
    reset.cancel()
    with pytest.raises(asyncio.CancelledError):
        await reset
    assert adapter._activity_queue.empty()
    await asyncio.wait_for(adapter._activity_queue.join(), 2)
    assert not adapter._activity_pending_event_ids
    assert not adapter._activity_pending_terminal_payloads
    assert all(timer.cancelled() for timer in timers)
    assert adapter._activity_sender_task is None
    assert set(adapter._activity_terminal_replay) == {'first', 'second'}
    ws = _FakeWebSocket()
    adapter._ws_active = True
    adapter._ws_connection = ws
    try:
        adapter._replay_terminal_activity(new_generation=True)
        await asyncio.wait_for(adapter._activity_queue.join(), 2)
        payloads = [decrypt_owner(frame[1], owner) for frame in ws.sent]
        assert {payload['turnId'] for payload in payloads} == {'first', 'second'}
        assert len(payloads) == 2
        for frame in ws.sent:
            assert adapter._handle_activity_ack(['OK', frame[1]['id'], True, 'stored'])
    finally:
        adapter._ws_active = False
        await adapter._reset_activity_transport()


@pytest.mark.asyncio
async def test_real_terminal_ack_cap_eviction_reconnect_and_late_ack(monkeypatch):
    from tests.gateway.test_buzz_activity_release import _buzz_mod
    owner = '02'.zfill(64)
    adapter = _make_adapter({'activity_owner_pubkey': nostr_auth.public_key_hex(owner)})
    monkeypatch.setattr(_buzz_mod, '_ACTIVITY_PENDING_CAP', 1)
    ws = _FakeWebSocket()
    adapter._ws_active = True
    adapter._ws_connection = ws
    try:
        adapter._enqueue_activity('turn_completed', channel_id='channel-1', session_id='s', turn_id='t')
        await asyncio.wait_for(adapter._activity_queue.join(), 2)
        old_id = ws.sent[0][1]['id']
        timer = adapter._activity_pending_event_ids[old_id][1]
        adapter._track_activity_ack('other-event', adapter._activity_ws_generation)
        assert timer.cancelled()
        assert list(adapter._activity_terminal_replay) == ['t']
        assert not adapter._handle_activity_ack(['OK', old_id, True, 'late'])
        adapter._ws_active = False
        await adapter._reset_activity_transport()
        replacement = _FakeWebSocket()
        adapter._ws_connection = replacement
        adapter._ws_active = True
        adapter._replay_terminal_activity(new_generation=True)
        await asyncio.wait_for(adapter._activity_queue.join(), 2)
        assert len(replacement.sent) == 1
        payload = decrypt_owner(replacement.sent[0][1], owner)
        assert payload['turnId'] == 't' and payload['kind'] == 'turn_completed'
        new_id = replacement.sent[0][1]['id']
        assert new_id != old_id
        assert not adapter._handle_activity_ack(['OK', old_id, True, 'late'])
        assert adapter._handle_activity_ack(['OK', new_id, True, 'stored'])
        assert not adapter._activity_pending_event_ids
        assert not adapter._activity_terminal_replay
    finally:
        adapter._ws_active = False
        await adapter._reset_activity_transport()
