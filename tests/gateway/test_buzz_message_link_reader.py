"""Installed canonical reader contract through bundled registration; no live transport."""
import json
import pytest
from hermes_cli.plugins import PluginContext, PluginManager, PluginManifest
from tools.registry import registry
from tests.gateway._plugin_adapter_loader import load_plugin_adapter

buzz = load_plugin_adapter('buzz')
CHANNEL = 'ccc2bc1a-7a82-5a8f-8c4e-57a070cbe7cd'
EVENT = '1' * 64
ROOT = '2' * 64
LINK = f'buzz://message?channel={CHANNEL}&id={EVENT}&thread={ROOT}'
SECRET = 'synthetic-reader-secret'

@pytest.fixture
def reader(monkeypatch, tmp_path):
    import hermes_cli.config as config
    monkeypatch.setattr(config, 'load_config', lambda: {})
    cli = tmp_path / 'buzz'
    cli.write_text('#!/bin/sh\n')
    monkeypatch.setenv('BUZZ_RELAY_URL', 'https://relay.example')
    monkeypatch.setenv('BUZZ_PRIVATE_KEY', SECRET)
    monkeypatch.setenv('BUZZ_CLI_PATH', str(cli))
    manager = PluginManager()
    ctx = PluginContext(PluginManifest(name='buzz'), manager)
    buzz.register(ctx)
    entry = registry.get_entry('buzz_read_message_link', scope=manager.scope_key)
    try:
        yield entry
    finally:
        manager.unload()

def test_registration_retains_core_tools(reader):
    assert reader is not None, 'bundled Buzz registration must expose canonical message reader'
    from toolsets import resolve_toolset
    from hermes_cli.tools_config import _get_platform_tools
    assert reader.is_async
    assert reader.check_fn()
    assert reader.schema['parameters']['required'] == ['link']
    from agent.secret_scope import set_secret_scope, reset_secret_scope
    # Prior aggregate cases intentionally activate multiplex mode. Supply this
    # test's synthetic profile scope; never disable the authorization guard.
    token = set_secret_scope({'BUZZ_PRIVATE_KEY': SECRET})
    try:
        assert {'terminal', 'file'} <= set(_get_platform_tools({}, 'buzz'))
        assert {'buzz_read_message_link', 'terminal', 'read_file', 'write_file'} <= set(resolve_toolset('hermes-buzz'))
    finally:
        reset_secret_scope(token)

@pytest.mark.asyncio
@pytest.mark.parametrize('link', [LINK.replace(EVENT, 'ABC'), LINK + '&id=' + EVENT, LINK + '&extra=1', LINK.replace(ROOT, ''), LINK + '#fragment'])
async def test_invalid_literal_never_looks_up(reader, monkeypatch, link):
    assert reader is not None, 'bundled Buzz registration must expose canonical message reader'
    async def forbidden(*a, **kw):
        pytest.fail('malformed literal must not reach CLI')
    monkeypatch.setattr(buzz, '_exec_buzz', forbidden)
    assert 'error' in json.loads(await reader.handler({'link': link}))

@pytest.mark.asyncio
@pytest.mark.parametrize('mode', ['exact', 'wrong-event', 'wrong-thread', 'stderr', 'malformed'])
async def test_exact_scope_and_sanitized_failures(reader, monkeypatch, mode):
    assert reader is not None, 'bundled Buzz registration must expose canonical message reader'
    calls = []
    async def transport(path, args, **kwargs):
        calls.append(args)
        assert SECRET not in ' '.join(args)
        assert kwargs['private_key'] == SECRET
        row = {'id': EVENT, 'content': 'exact content', 'created_at': 1234, 'pubkey': '3'*64, 'tags': [['e', ROOT, '', 'root']]}
        if mode == 'wrong-event': row['id'] = '4'*64
        if mode == 'wrong-thread': row['tags'] = [['e', '4'*64, '', 'root']]
        if mode == 'stderr': return 2, '', 'rejected ' + SECRET
        if mode == 'malformed': return 0, '{}', ''
        return 0, json.dumps([row]), ''
    monkeypatch.setattr(buzz, '_exec_buzz', transport)
    raw = await reader.handler({'link': LINK})
    result = json.loads(raw)
    assert SECRET not in raw
    assert calls == [['messages', 'get', '--channel', CHANNEL, '--limit', '500']]
    if mode == 'exact':
        assert result == dict(channel=CHANNEL, id=EVENT, thread=ROOT, pubkey='3'*64, created_at=1234, content='exact content')
    else:
        errors = {'wrong-event': 'linked Buzz message was not found', 'wrong-thread': 'linked event does not belong to the requested thread', 'stderr': 'Buzz CLI failed (exit 2)', 'malformed': 'buzz messages get returned malformed data'}
        assert result == {'error': errors[mode]}

@pytest.mark.asyncio
@pytest.mark.parametrize('mode,expected_calls', [('found',2), ('stalled',2), ('bounded',20), ('bad-timestamp',1)])
async def test_bounded_pagination(reader, monkeypatch, mode, expected_calls):
    assert reader is not None, 'bundled Buzz registration must expose canonical message reader'
    calls = []
    async def transport(path, args, **kwargs):
        calls.append(args)
        if mode == 'found' and len(calls) == 2:
            return 0, json.dumps([{'id': EVENT, 'content': 'older', 'tags': [['e', ROOT, '', 'root']]}]), ''
        timestamp = 10000 if mode == 'stalled' else 10000 - len(calls)
        if mode == 'bad-timestamp': timestamp = True
        return 0, json.dumps([{'id': '4'*64, 'created_at': timestamp}]*500), ''
    monkeypatch.setattr(buzz, '_exec_buzz', transport)
    result = json.loads(await reader.handler({'link': LINK}))
    assert len(calls) == expected_calls
    assert all(c[:7] == ['messages','get','--channel',CHANNEL,'--limit','500'][:7] for c in calls[:1])
    if mode == 'found':
        assert result['id'] == EVENT
        assert calls[1][-2:] == ['--before','9999']
    else:
        expected = {'stalled':'buzz message pagination did not advance', 'bounded':'linked Buzz message was not found', 'bad-timestamp':'buzz messages get returned malformed pagination data'}
        assert result == {'error': expected[mode]}
