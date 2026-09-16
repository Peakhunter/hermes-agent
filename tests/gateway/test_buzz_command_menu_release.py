"""Buzz command-menu labels reach the current shared event parser unchanged."""
import pytest
from gateway.platforms.event import MessageEvent
from tests.gateway.test_buzz_adapter import (
    _clean_env, release_owner_policy, release_central_intake, _event, CHANNEL,
    OTHER_PUBKEY, _release_emit,
)


@pytest.mark.parametrize('text,command,args', [
    ('/status…', 'status', ''),
    ('  /WHOAMI…@Chip', 'whoami', ''),
    ('/resume… session-id', 'resume', 'session-id'),
    ('/model… —now model…', 'model', '--now model…'),
    ('/status@Chip…', 'status', ''),
    ('/status', 'status', ''),
    ('/status...', 'status...', ''),
    ('/sta…tus', 'sta…tus', ''),
    ('/tmp/path…', None, ''),
    ('', None, ''),
    ('ordinary…', None, 'ordinary…'),
])
def test_command_menu_suffix_does_not_change_arguments_or_path_guard(text, command, args):
    event = MessageEvent(text=text)
    assert event.get_command() == command
    assert event.get_command_args() == args
    assert event.text == text


@pytest.mark.parametrize('text', ['/approve… session-id', '/whoami…', '/deny…'])
def test_untrusted_menu_text_cannot_gain_gateway_control(text):
    event = MessageEvent(text=text, allow_gateway_control=False)
    assert not event.is_command()
    assert event.get_command() is None
    assert event.get_command_args() == text


@pytest.mark.asyncio
async def test_buzz_menu_whoami_runs_real_authorized_command(release_central_intake):
    f = release_central_intake
    f.save(allowed_users=[OTHER_PUBKEY], require_mention=True, thread_require_mention=True)
    event = _event('menu-command', content='@Chip /whoami…')
    assert MessageEvent(text=f.adapter._strip_mention(event['content'])).get_command() == 'whoami'
    await _release_emit(f, event)
    f.handler.assert_awaited_once()
    assert f.handler.call_args.args[0].get_command() == 'whoami'
    assert f.adapter.send.await_count == 1
    assert OTHER_PUBKEY in f.adapter.send.call_args.kwargs['content']
