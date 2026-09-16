"""Characterize retained clarify/resume/durable completion paths, no live services.

Real runner, session DB/store, clarify worker, async ledger and Buzz/base admission.
Only CLI transport and the final model boundary are synthetic.
"""
import asyncio
import dataclasses
import json
import queue
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from tests.gateway.test_buzz_adapter import (
    _clean_env, release_owner_policy, release_central_intake,
    _event, CHANNEL, OTHER_PUBKEY,
)
from tests.gateway.test_buzz_routing_release import nested


async def emit(f, event, *, wait=True):
    before = set(f.adapter._session_tasks.values())
    await f.adapter._handle_event(CHANNEL, f.adapter._channel_state[CHANNEL], event)
    tasks = set(f.adapter._session_tasks.values()) - before
    if wait and tasks:
        await asyncio.wait_for(asyncio.gather(*tasks), 5)


async def initial(f):
    f.save(allowed_users=[OTHER_PUBKEY], require_mention=True, thread_require_mention=True)
    await emit(f, _event('origin-root', content='@Chip /whoami'))
    source = f.handler.call_args.args[0].source
    return source, f.runner._session_key_for_source(source)


@pytest.mark.asyncio
@pytest.mark.parametrize('finish', ['answer', 'cancel', 'served-other'])
async def test_real_clarify_worker_publication_and_strict_reply(finish, release_central_intake):
    from gateway.run_turn_runner import TurnRunner
    from gateway.run import _AGENT_PENDING_SENTINEL
    from tools import clarify_gateway as cm
    f = release_central_intake
    a, r = f.adapter, f.runner
    if finish == 'served-other':
        from gateway.profile_routing import parse_profile_routes
        home = r.config.sessions_dir.parent / 'profiles' / 'other'
        home.mkdir(parents=True)
        (home / 'config.yaml').write_text('{}\n')
        (home / '.env').write_text(f'GATEWAY_ALLOWED_USERS={OTHER_PUBKEY}\n')
        r.config.multiplex_profiles = True
        r.config.multiplex_profile_allowlist = ['other']
        r.config.profile_routes = parse_profile_routes([
            {'name': 'original', 'platform': 'buzz', 'chat_id': CHANNEL, 'profile': 'default'}])
    source, key = await initial(f)
    a.send = type(a).send.__get__(a)
    sent, ready = [], asyncio.Event()

    async def cli(args, **kwargs):
        if args[:2] == ['messages', 'send']:
            sent.append((args, kwargs.get('input_text')))
            ready.set()
            return 0, json.dumps({'accepted': True, 'event_id': 'clarify-prompt'}), ''
        return 0, '{}', ''

    a._run_cli = cli
    ctx = SimpleNamespace(_status_adapter=a, session_key=key, _status_chat_id=CHANNEL,
        _status_thread_metadata=r._thread_metadata_for_source(source),
        _loop_for_step=asyncio.get_running_loop(), stream_consumer_holder=[None])
    worker = TurnRunner(r, ctx)
    r._session_state(key).turn.agent = _AGENT_PENDING_SENTINEL
    waiter = asyncio.create_task(asyncio.to_thread(worker._clarify_callback_sync, 'Choose', ['A', 'B']))
    a._active_sessions[key] = asyncio.Event()
    a._session_tasks[key] = waiter
    try:
        await asyncio.wait_for(ready.wait(), 5)
        pending = cm.get_pending_for_session(key, include_choice_prompts=True)
        assert pending is not None
        args = sent[0][0]
        assert args[args.index('--reply-to') + 1] == source.thread_id
        # Installed strict mentions have no arbitrary text/clarify bypass. Keep it.
        for eid, user, parent, text in [
            ('plain', OTHER_PUBKEY, 'clarify-prompt', '1'),
            ('wrong-thread', OTHER_PUBKEY, 'different-root', '1'),
            ('wrong-user', '9' * 64, 'clarify-prompt', '@Chip 1'),
        ]:
            evt = nested(eid, parent, pubkey=user)
            evt['content'] = text
            await emit(f, evt)
            assert not pending.event.is_set() and not waiter.done()
        if finish == 'served-other':
            original_routes = r.config.profile_routes
            r.config.profile_routes = parse_profile_routes([
                {'name': 'other', 'platform': 'buzz', 'chat_id': CHANNEL, 'profile': 'other'}])
            other_source = a.build_source(chat_id=CHANNEL, chat_type='group',
                user_id=OTHER_PUBKEY, thread_id=source.thread_id)
            other_key = r._session_key_for_source(other_source)
            assert other_source.profile == 'other' and other_key != key
            assert r._is_user_authorized_for_source(other_source)
            other_pending = cm.register('other-clarify', other_key, 'Other question', ['A', 'B'])
            try:
                reply = nested('other-answer', 'clarify-prompt')
                reply['content'] = '@Chip 1'
                await emit(f, reply)
                assert other_pending.response == 'A' and other_pending.event.is_set()
                assert not pending.event.is_set() and not waiter.done()
            finally:
                cm.clear_session(other_key)
                r.config.profile_routes = original_routes
        if finish == 'cancel':
            assert cm.clear_session(key) == 1
            assert (await asyncio.wait_for(waiter, 5)).startswith('[')
        else:
            reply = nested('answer', 'clarify-prompt')
            reply['content'] = '@Chip 1'
            await emit(f, reply)
            assert await asyncio.wait_for(waiter, 5) == 'A'
        assert not cm.has_pending(key)
    finally:
        cm.clear_session(key)
        await asyncio.wait_for(waiter, 5)
        a._active_sessions.clear()
        a._session_tasks.clear()
        if r._session_db is not None:
            await r._session_db.close()


async def resume_origin(f):
    source, key = await initial(f)
    r = f.runner
    target = await r.async_session_store.get_or_create_session(source)
    await r._session_db.set_session_title(target.session_id, 'Routing original')
    replacement = await r.async_session_store.reset_session(key)
    assert replacement.session_id != target.session_id
    r._session_sources.clear()
    command = nested('resume-command', source.thread_id)
    command['content'] = '@Chip /resume ' + target.session_id
    await emit(f, command)
    assert r.session_store.peek_session_id(key) == target.session_id
    assert 'Routing original' in f.adapter.send.call_args.kwargs['content']
    await emit(f, nested('next-turn', source.thread_id))
    assert r._session_key_for_source(f.handler.call_args.args[0].source) == key
    assert r.session_store.peek_session_id(key) == target.session_id
    return source, key, target.session_id


@pytest.mark.asyncio
async def test_resume_and_durable_async_cold_recovery_to_real_buzz(release_central_intake):
    from tools import async_delegation as ad
    from tools.process_registry import process_registry
    from gateway.session_context import set_session_vars, clear_session_vars
    from gateway.session import SessionStore
    f = release_central_intake
    a, r = f.adapter, f.runner
    source, key, sid = await resume_origin(f)
    foreground_source = dataclasses.replace(source, thread_id='other-root')
    foreground_key = r._session_key_for_source(foreground_source)
    foreground_guard = asyncio.Event()
    foreground_task = asyncio.create_task(foreground_guard.wait())
    a._active_sessions[foreground_key] = foreground_guard
    a._session_tasks[foreground_key] = foreground_task
    ad._reset_for_tests()
    tokens = set_session_vars(platform='buzz', chat_id=CHANNEL, thread_id=source.thread_id,
        user_id=OTHER_PUBKEY, user_name='Parent', scope_id='owner-scope', session_key=key)

    def child():
        child_tokens = set_session_vars(user_id='wrong-child', scope_id='wrong-scope', thread_id='wrong-thread')
        try:
            return {'status': 'completed', 'summary': 'Synthetic completion'}
        finally:
            clear_session_vars(child_tokens)

    try:
        handle = ad.dispatch_async_delegation(goal='Synthetic', context=None, toolsets=[],
            role='researcher', model=None, session_key=key, parent_session_id=sid, runner=child)
        assert handle['status'] == 'dispatched'
        live = await asyncio.wait_for(asyncio.to_thread(process_registry.completion_queue.get, True, 5), 6)
        assert live['delegation_id'] == handle['delegation_id']
        assert live['user_id'] == OTHER_PUBKEY and live['scope_id'] == 'owner-scope'
        assert live['user_name'] == 'Parent'
        recovered = queue.Queue()
        assert ad.restore_undelivered_completions(recovered) == 1
        evt = recovered.get_nowait()
        assert evt['restored'] is True and evt['session_key'] == key
        assert evt['user_id'] == OTHER_PUBKEY and evt['scope_id'] == 'owner-scope'
        r._session_sources.clear()
        # Real disk reload, not retained foreground source or preloaded entry.
        r.session_store = SessionStore(r.config.sessions_dir, r.config)
        assert not r.session_store._entries
        r._cache_session_source(foreground_key, foreground_source)
        r._enrich_async_delegation_routing(evt)
        rebuilt = r._build_process_event_source(evt)
        assert rebuilt.thread_id == source.thread_id and rebuilt.chat_id == CHANNEL
        assert r._resolve_injection_adapter('buzz', rebuilt) is a
        # Characterize an inherited limitation, NOT an installed routing loss:
        # group-key suffixes are ambiguous (thread vs user) in BOTH versions.
        # Without saved origin, admission must refuse rather than reroute.
        entries = r.session_store._entries
        r.session_store._entries = {}
        try:
            legacy = r._build_process_event_source(evt)
            assert key.split(':')[3] == 'group' and legacy.thread_id is None
            assert legacy.user_id == OTHER_PUBKEY and legacy.scope_id == 'owner-scope'
            assert await r._deliver_completion_notification('Synthetic completion', evt) is False
            assert ad.get_durable_delegation(handle['delegation_id'])['delivery_attempts'] == 0
        finally:
            r.session_store._entries = entries
        # No transport must not spend an attempt.
        r.adapters.clear()
        assert await r._deliver_completion_notification('Synthetic completion', evt) is False
        assert ad.get_durable_delegation(handle['delegation_id'])['delivery_attempts'] == 0
        r.adapters[a.platform] = a
        handler = a._message_handler
        a.set_message_handler(None)
        assert await r._deliver_completion_notification('Synthetic completion', evt) is False
        row = ad.get_durable_delegation(handle['delegation_id'])
        assert row['delivery_state'] == 'pending' and row['delivery_attempts'] == 0
        a.set_message_handler(handler)
        a.send = type(a).send.__get__(a)
        published = []
        async def cli(args, **kwargs):
            if args[:2] == ['messages', 'send']:
                published.append((args, kwargs.get('input_text')))
                return 0, json.dumps({'accepted': True, 'event_id': 'completion-reply'}), ''
            return 0, '{}', ''
        a._run_cli = cli
        # Exercise actual runner command response instead of making a model call.
        assert await r._deliver_completion_notification('/whoami', evt) is True
        await asyncio.wait_for(asyncio.gather(*(t for t in a._session_tasks.values()
                                              if t is not foreground_task)), 5)
        internal = f.handler.call_args.args[0]
        assert internal.internal and internal._gateway_accepted is True
        assert internal.source.thread_id == source.thread_id
        assert internal.metadata['gateway_session_id'] == sid
        assert ad.get_durable_delegation(handle['delegation_id'])['delivery_state'] == 'delivered'
        args, text = published[-1]
        assert args[args.index('--reply-to') + 1] == source.thread_id
        assert OTHER_PUBKEY in text
        assert a._active_sessions[foreground_key] is foreground_guard
        assert not foreground_task.done() and foreground_key not in a._pending_messages
    finally:
        foreground_guard.set()
        await foreground_task
        a._active_sessions.pop(foreground_key, None)
        a._session_tasks.pop(foreground_key, None)
        clear_session_vars(tokens)
        ad._reset_for_tests()
        if r._session_db is not None:
            await r._session_db.close()


@pytest.mark.asyncio
@pytest.mark.parametrize('key', ['agent:main:buzz:thread:legacy-chat:legacy-root', '', 'malformed'])
async def test_legacy_and_malformed_completion_origin(release_central_intake, key):
    f = release_central_intake
    evt = {'type': 'async_delegation', 'session_key': key, 'user_id': OTHER_PUBKEY}
    f.runner._enrich_async_delegation_routing(evt)
    source = f.runner._build_process_event_source(evt)
    if key.startswith('agent:'):
        assert source.thread_id == 'legacy-root' and source.chat_id == 'legacy-chat'
        assert f.runner._resolve_injection_adapter('buzz', source) is f.adapter
        source.profile = 'unserved'
        assert f.runner._resolve_injection_adapter('buzz', source) is None
    else:
        assert source is None
        assert await f.runner._completion_delivery_ready(evt) is False


@pytest.mark.asyncio
async def test_api_server_async_completion_is_durable_not_a_wake(release_central_intake, tmp_path, monkeypatch):
    import gateway.wake as wake
    self_post = AsyncMock(side_effect=AssertionError('must not start an autonomous turn'))
    monkeypatch.setattr(wake, '_self_post_chat_completion', self_post)
    from hermes_state import SessionDB
    db = SessionDB(db_path=tmp_path / 'synthetic-api.db')
    db.create_session('api-origin', source='api_server')
    adapter = SimpleNamespace(_ensure_session_db=lambda: db, supports_async_delivery=False)
    try:
        assert await release_central_intake.runner._self_post_api_server(adapter, 'finished', 'api-origin',
            {'type': 'async_delegation', 'delegation_id': 'api-child'}) is True
        messages = db.get_messages('api-origin')
        assert len(messages) == 1
        # Bookkeeping rows deliberately use user role; no model turn is started.
        self_post.assert_not_awaited()
        assert messages[0]['display_kind'] == 'async_delegation_complete'
        assert 'finished' in messages[0]['content']
    finally:
        db.close()
