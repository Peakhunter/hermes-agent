"""Installed Buzz routing contracts through current intake and publication."""
import asyncio
import pytest
from tests.gateway.test_buzz_adapter import (
    _clean_env, release_owner_policy, release_central_intake,
    _event, _release_emit, CHANNEL, OTHER_PUBKEY,
)
from gateway.session import build_session_key
import json
from unittest.mock import AsyncMock
from tests.gateway.test_buzz_adapter import _make_adapter, SELF_PUBKEY


def nested(event_id, parent, *, channel=CHANNEL, marked=True, pubkey=OTHER_PUBKEY):
    event = _event(event_id, pubkey=pubkey, content='@Chip /whoami')
    event['tags'] = [['h', channel], ['e', parent, '', 'reply'] if marked else ['e', parent]]
    return event


@pytest.mark.asyncio
@pytest.mark.parametrize('marked', [True, False])
async def test_newest_first_seed_routes_dispatch_and_send_without_echo(release_central_intake, marked):
    f = release_central_intake
    f.save(allowed_users=[OTHER_PUBKEY], require_mention=True, thread_require_mention=True)
    a = f.adapter
    a._run_cli = AsyncMock(return_value=(0, json.dumps([
        nested('leaf', 'middle', marked=marked), nested('middle', 'original', marked=marked),
        _event('original')]), ''))
    await a._seed_channel(CHANNEL, 'group')
    assert f.handler.await_count == 0
    await _release_emit(f, nested('new-child', 'leaf', marked=marked))
    assert f.handler.call_args.args[0].source.thread_id == 'original'
    # Restore real publisher (fixture stubs transport); no relay echo is injected.
    a.send = type(a).send.__get__(a)
    a._run_cli = AsyncMock(return_value=(0, json.dumps({'accepted': True, 'event_id': 'outgoing'}), ''))
    result = await a.send(CHANNEL, 'answer', reply_to='leaf')
    assert result.success
    args = a._run_cli.call_args.args[0]
    assert args[args.index('--reply-to') + 1] == 'original'
    await a._handle_event(CHANNEL, a._channel_state[CHANNEL], nested('after-send', 'outgoing'))
    await asyncio.gather(*tuple(a._session_tasks.values()))
    assert f.handler.call_args.args[0].source.thread_id == 'original'



@pytest.mark.asyncio
@pytest.mark.parametrize('kind', ['image', 'file', 'url'])
async def test_attachment_receipt_preserves_noecho_root(release_central_intake, tmp_path, kind):
    f = release_central_intake
    f.save(allowed_users=[OTHER_PUBKEY], require_mention=True, thread_require_mention=True)
    a = f.adapter
    path = tmp_path / 'image.png'
    path.write_bytes(b'not-a-real-image')
    a._run_cli = AsyncMock(return_value=(0, json.dumps({'accepted': True, 'event_id': 'media-out'}), ''))
    if kind == 'image':
        result = await a.send_image_file(CHANNEL, str(path), reply_to='media-root')
    elif kind == 'url':
        stub_send = a.send
        a.send = type(a).send.__get__(a)
        result = await a.send_image(CHANNEL, 'https://example.invalid/image.png', reply_to='media-root')
        a.send = stub_send
    else:
        result = await a.send_document(CHANNEL, str(path), reply_to='media-root')
    assert result.success
    await _release_emit(f, nested('media-followup', 'media-out'))
    assert f.handler.call_args.args[0].source.thread_id == 'media-root'


@pytest.mark.asyncio
async def test_seed_ancestry_is_scoped_to_channel(release_central_intake):
    f = release_central_intake
    f.save(allowed_users=[OTHER_PUBKEY], require_mention=True, thread_require_mention=True)
    a = f.adapter
    for channel, root in [(CHANNEL, 'our-root'), ('second-channel', 'their-root')]:
        a._run_cli = AsyncMock(return_value=(0, json.dumps([nested('same-id', root, channel=channel)]), ''))
        await a._seed_channel(channel, 'group')
    await _release_emit(f, nested('ours', 'same-id'))
    assert f.handler.call_args.args[0].source.thread_id == 'our-root'
    await a._handle_event('second-channel', a._channel_state['second-channel'],
                         nested('theirs', 'same-id', channel='second-channel'))
    await asyncio.gather(*tuple(a._session_tasks.values()))
    assert f.handler.call_args.args[0].source.thread_id == 'their-root'


@pytest.mark.asyncio
async def test_self_echo_ancestry_is_routing_not_mention_authority(release_central_intake):
    f = release_central_intake
    f.save(allowed_users=[OTHER_PUBKEY], require_mention=True, thread_require_mention=True)
    a = f.adapter
    await a._handle_event(CHANNEL, a._channel_state[CHANNEL], nested('self-child', 'echo-root', pubkey=SELF_PUBKEY))
    assert f.handler.await_count == 0
    unmentioned = nested('ordinary', 'self-child')
    unmentioned['content'] = 'not a control'
    await a._handle_event(CHANNEL, a._channel_state[CHANNEL], unmentioned)
    assert f.handler.await_count == 0
    await _release_emit(f, nested('mentioned', 'self-child'))
    assert f.handler.call_args.args[0].source.thread_id == 'echo-root'


@pytest.mark.asyncio
async def test_initial_and_followup_share_real_dispatch_session(release_central_intake):
    f = release_central_intake
    f.save(allowed_users=[OTHER_PUBKEY], require_mention=True, thread_require_mention=True)
    await _release_emit(f, _event('root-one', content='@Chip /whoami'))
    initial = f.handler.call_args.args[0].source
    assert initial.thread_id == 'root-one'
    reply = _event('followup-one', content='@Chip /whoami')
    reply['tags'].append(['e', 'root-one', '', 'reply'])
    await _release_emit(f, reply)
    followup = f.handler.call_args.args[0].source
    assert build_session_key(initial) == build_session_key(followup)
    assert f.adapter.send.await_count == 2


@pytest.mark.asyncio
async def test_concurrent_roots_do_not_exchange_sources(release_central_intake):
    f = release_central_intake
    f.save(allowed_users=[OTHER_PUBKEY], require_mention=True, thread_require_mention=False)
    a = f.adapter
    await asyncio.gather(*(a._handle_event(CHANNEL, a._channel_state[CHANNEL],
        _event(root, content='@Chip /whoami')) for root in ('root-a', 'root-b')))
    await asyncio.gather(*tuple(a._session_tasks.values()))
    sources = {c.args[0].message_id: c.args[0].source for c in f.handler.call_args_list}
    assert {k: v.thread_id for k, v in sources.items()} == {'root-a': 'root-a', 'root-b': 'root-b'}
    assert len({build_session_key(s) for s in sources.values()}) == 2
    # Synthetic routing roots must not classify ordinary channel traffic as relaxed threads.
    await a._handle_event(CHANNEL, a._channel_state[CHANNEL], _event('unmentioned', content='/whoami'))
    assert f.handler.await_count == 2


@pytest.mark.asyncio
async def test_dm_root_and_cyclic_seed_are_bounded(release_central_intake):
    f = release_central_intake
    f.save(allowed_users=[OTHER_PUBKEY], require_mention=True, thread_require_mention=True)
    a = f.adapter
    a._channel_state[CHANNEL]['chat_type'] = 'dm'
    a._channel_meta[CHANNEL] = {'name': 'DM', 'description': 'DM'}
    await a._handle_event(CHANNEL, a._channel_state[CHANNEL], _event('dm-top', content='@Chip /whoami'))
    await asyncio.gather(*tuple(a._session_tasks.values()))
    assert f.handler.call_args.args[0].source.thread_id is None
    await a._handle_event(CHANNEL, a._channel_state[CHANNEL], nested('dm-next', 'dm-top'))
    await asyncio.gather(*tuple(a._session_tasks.values()))
    assert f.handler.call_args.args[0].source.thread_id == 'dm-top'
    a._run_cli = AsyncMock(return_value=(0, json.dumps([
        nested('cycle-a', 'cycle-b'), nested('cycle-b', 'cycle-a')]), ''))
    await a._seed_channel(CHANNEL, 'group')
    # Neither corrupt/cyclic history nor an unknown parent can hang publication.
    a._run_cli = AsyncMock(return_value=(0, json.dumps({'accepted': True, 'event_id': 'cycle-out'}), ''))
    a.send = type(a).send.__get__(a)
    for anchor in ('cycle-a', 'unknown'):
        result = await asyncio.wait_for(a.send(CHANNEL, 'answer', reply_to=anchor), 2)
        assert result.success
        args = a._run_cli.call_args.args[0]
        assert args[args.index('--reply-to') + 1] == anchor
