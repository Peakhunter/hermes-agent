"""Configured identities are handoffs, not best-effort display-name guesses.

Production adapter/CLI argv boundary; only the external CLI is synthetic.
Installed configured-mention contract adapted to current reply and fallback rules.
"""
import json

import pytest

from tests.gateway.test_buzz_adapter import (
    _buzz_mod as buzz, _make_adapter, _clean_env, CHANNEL,
)

TARGET = 'c' * 64
SPOOF = 'd' * 64


@pytest.mark.asyncio
async def test_configured_identity_overrides_member_display_name_collision():
    adapter = _make_adapter(extra={'outbound_mention_pubkeys': {'ClaudeCode': TARGET}})
    calls = []

    async def cli(args, *, input_text=None):
        calls.append((list(args), input_text))
        if args[:2] == ['channels', 'members']:
            return 0, json.dumps([{'pubkey': SPOOF}]), ''
        if args[:2] == ['users', 'get']:
            return 0, json.dumps([{'display_name': 'ClaudeCode'}]), ''
        assert args[:2] == ['messages', 'send']
        return 0, json.dumps({'accepted': True, 'event_id': 'handoff'}), ''

    adapter._run_cli = cli
    result = await adapter.send(CHANNEL, '@ClaudeCode review', reply_to='immediate',
                                metadata={'thread_id': 'root'})
    assert result.success
    sends = [(a, t) for a, t in calls if a[:2] == ['messages', 'send']]
    assert len(sends) == 1
    args, text = sends[0]
    assert [args[i+1] for i, a in enumerate(args) if a == '--mention'] == [TARGET]
    assert args[args.index('--reply-to')+1] == 'root'
    assert text == '@ClaudeCode review'


@pytest.mark.parametrize('value,match', [
    (['not-a-map'], 'must be a mapping'),
    ({'ClaudeCode': 'not-a-key'}, 'valid hex or npub'),
    ({'': TARGET}, 'display name'),
    ({'ClaudeCode': TARGET, '@claudecode': SPOOF}, 'duplicate display name'),
])
def test_invalid_configuration_fails_visibly(value, match):
    with pytest.raises(ValueError, match=match):
        _make_adapter(extra={'outbound_mention_pubkeys': value})


def test_npub_and_display_alias_normalization():
    adapter = _make_adapter(extra={'outbound_mention_pubkeys': {
        ' @ClaudeCode ': buzz.hex_to_npub(TARGET)}})
    assert adapter.outbound_mention_pubkeys == {'claudecode': ('ClaudeCode', TARGET)}


async def exercise(path, content, replies, tmp_path, monkeypatch, mapping=None):
    from gateway.config import PlatformConfig
    extra = {'relay_url': 'https://test.relay', 'cli_path': '/synthetic/buzz',
             'outbound_mention_pubkeys': mapping or {'ClaudeCode': TARGET}}
    adapter = _make_adapter(extra=extra)
    sends = []

    async def cli(args, *, input_text=None):
        if args[:2] != ['messages', 'send']:
            return 0, '[]', ''
        sends.append((list(args), input_text))
        return replies[min(len(sends)-1, len(replies)-1)]

    adapter._run_cli = cli
    file = tmp_path / 'image.png'
    file.write_bytes(b'synthetic image upload')
    if path.startswith('standalone'):
        monkeypatch.setattr(buzz, '_configured_cli_path', lambda *_: '/synthetic/buzz')
        monkeypatch.setattr(buzz, '_resolve_private_key', lambda *_: 'synthetic-key')
        async def execute(_cli, args, **kwargs):
            return await cli(args, input_text=kwargs.get('input_text'))
        monkeypatch.setattr(buzz, '_exec_buzz', execute)
        result = await buzz._standalone_send(
            PlatformConfig(enabled=True, extra=extra), CHANNEL, content,
            thread_id='root', media_files=[str(file)] if path.endswith('image') else None)
        success, error = result.get('success', False), result.get('error')
    else:
        kwargs = {'metadata': {'thread_id': 'root'}}
        if path == 'text':
            result = await adapter.send(CHANNEL, content, **kwargs)
        elif path == 'url':
            result = await adapter.send_image(CHANNEL, 'https://image.invalid/a.png', caption=content, **kwargs)
        else:
            method = getattr(adapter, path)
            result = await method(CHANNEL, str(file), caption=content, **kwargs)
        success, error = result.success, result.error
    return success, error, sends


SUCCESS = (0, json.dumps({'accepted': True, 'event_id': 'handoff'}), '')
PATHS = ['text', 'send_image', 'send_image_file', 'url', 'send_document',
         'send_video', 'send_voice', 'standalone', 'standalone-image']


@pytest.mark.asyncio
@pytest.mark.parametrize('path', PATHS)
async def test_all_publish_paths_keep_configured_structural_identity(path, tmp_path, monkeypatch):
    success, error, sends = await exercise(path, '@ClaudeCode review', [SUCCESS], tmp_path, monkeypatch)
    assert success, error
    assert len(sends) == 1
    args, text = sends[0]
    assert [args[i+1] for i, a in enumerate(args) if a == '--mention'] == [TARGET]
    assert args[args.index('--reply-to')+1] == 'root'
    assert text.startswith('@ClaudeCode review')
    if path not in ('text', 'url', 'standalone'):
        assert '--file' in args


@pytest.mark.asyncio
@pytest.mark.parametrize('path', ['text', 'send_image_file', 'standalone-image'])
@pytest.mark.parametrize('error', [
    "mention '@ClaudeCode' does not match a current channel member",
    'explicit pubkeys are not channel members',
])
async def test_configured_handoff_cannot_report_plain_text_success(path, error, tmp_path, monkeypatch):
    success, visible_error, sends = await exercise(
        path, '@ClaudeCode review', [(1, '', error), SUCCESS], tmp_path, monkeypatch)
    assert not success
    assert error in visible_error
    assert len(sends) == 1
    args, text = sends[0]
    assert '--mention' in args and TARGET in args
    assert text == '@ClaudeCode review'


@pytest.mark.asyncio
@pytest.mark.parametrize('path', ['text', 'send_image_file', 'standalone'])
async def test_ordinary_fallback_retains_configured_identity(path, tmp_path, monkeypatch):
    failure = (1, '', "mention '@ghost' does not match a current channel member")
    success, error, sends = await exercise(path, '@ClaudeCode ask @ghost', [failure, SUCCESS], tmp_path, monkeypatch)
    assert success, error
    assert len(sends) == 2
    assert sends[0][0] == sends[1][0]
    assert TARGET in sends[1][0]
    assert sends[1][1] == '@ClaudeCode ask @\u200bghost'


@pytest.mark.asyncio
@pytest.mark.parametrize('content', [
    '@ClaudeCodeX review', '@ClaudeCode.bot review', '@ClaudeCode-agent review',
    '@ClaudeCode\u0301 review', 'email@ClaudeCode review', '@@ClaudeCode review',
])
async def test_partial_aliases_never_gain_configured_authority(content, tmp_path, monkeypatch):
    success, error, sends = await exercise('text', content, [SUCCESS], tmp_path, monkeypatch)
    assert success, error
    assert '--mention' not in sends[0][0]


@pytest.mark.asyncio
async def test_unicode_casefold_handoff(tmp_path, monkeypatch):
    success, error, sends = await exercise('text', '@STRASSE review', [SUCCESS], tmp_path,
                                         monkeypatch, {'Straße': TARGET})
    assert success, error
    assert TARGET in sends[0][0]


@pytest.mark.asyncio
@pytest.mark.parametrize('path', ['text', 'send_image_file', 'standalone'])
async def test_cancelled_publish_propagates_without_fallback(path, tmp_path, monkeypatch):
    import asyncio
    class CancelOnSend:
        def __len__(self):
            return 1
        def __getitem__(self, _index):
            raise asyncio.CancelledError
    with pytest.raises(asyncio.CancelledError):
        await exercise(path, '@ClaudeCode review', CancelOnSend(), tmp_path, monkeypatch)


@pytest.mark.asyncio
async def test_member_drift_drops_only_dynamic_identity():
    adapter = _make_adapter(extra={'outbound_mention_pubkeys': {'ClaudeCode': TARGET}})
    calls = []
    async def cli(args, *, input_text=None):
        if args[:2] == ['channels', 'members']:
            return 0, json.dumps([{'pubkey': SPOOF}]), ''
        if args[:2] == ['users', 'get']:
            return 0, json.dumps([{'display_name': 'Human'}]), ''
        calls.append((list(args), input_text))
        return (1, '', 'pubkeys are not channel members') if len(calls) == 1 else SUCCESS
    adapter._run_cli = cli
    result = await adapter.send(CHANNEL, '@ClaudeCode ask @Human')
    assert result.success
    assert len(calls) == 2
    assert TARGET in calls[0][0] and SPOOF in calls[0][0]
    assert TARGET in calls[1][0] and SPOOF not in calls[1][0]
    assert calls[0][1] == calls[1][1] == '@ClaudeCode ask @Human'


@pytest.mark.asyncio
async def test_standalone_invalid_mapping_is_visible_before_publish(monkeypatch):
    from gateway.config import PlatformConfig
    from unittest.mock import AsyncMock
    monkeypatch.setattr(buzz, '_configured_cli_path', lambda *_: '/synthetic/buzz')
    monkeypatch.setattr(buzz, '_resolve_private_key', lambda *_: 'synthetic-key')
    execute = AsyncMock(return_value=SUCCESS)
    monkeypatch.setattr(buzz, '_exec_buzz', execute)
    result = await buzz._standalone_send(PlatformConfig(enabled=True, extra={
        'relay_url': 'https://test.relay', 'outbound_mention_pubkeys': {'ClaudeCode': 'bad'}
    }), CHANNEL, '@ClaudeCode review')
    assert 'valid hex or npub' in result['error']
    execute.assert_not_awaited()
