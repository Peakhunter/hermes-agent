"""Exercise the current release wrapper/worker and delivery seams, not a replaced run.py."""
import asyncio
from contextlib import nullcontext
from types import SimpleNamespace
import pytest
from gateway.run import GatewayRunner
from gateway.session import SessionSource
from gateway.config import Platform

class Capture:
    def __init__(self): self.events = []
    def on_turn_lifecycle(self, event):
        self.events.append(event)
        return True

def runner_for(route):
    runner = object.__new__(GatewayRunner)
    runner._profile_scope_for_source = lambda source: nullcontext()
    runner._adapter_for_source = lambda source: route
    runner._is_session_run_current = lambda *args: True
    return runner

def source():
    return SessionSource(platform=Platform('buzz'), chat_id='channel-1', user_id='owner', chat_type='group', thread_id='thread-1')

@pytest.mark.asyncio
@pytest.mark.parametrize('outcome', ['success', 'failed', 'cancelled', 'exception'])
async def test_current_proxy_wrapper_terminal(outcome):
    route = Capture()
    runner = runner_for(route)
    runner._get_proxy_url = lambda: 'http://proxy.invalid'
    async def proxy(**kwargs):
        if outcome == 'cancelled': raise asyncio.CancelledError
        if outcome == 'exception': raise RuntimeError('private-error')
        return {'final_response': 'private-response', 'failed': outcome == 'failed'}
    runner._run_agent_via_proxy = proxy
    if outcome in {'cancelled', 'exception'}:
        with pytest.raises(asyncio.CancelledError if outcome == 'cancelled' else RuntimeError):
            await runner._run_agent('private-prompt', '', [], source(), 'session-1', session_key='key', event_message_id='a'*64)
    else:
        result = await runner._run_agent('private-prompt', '', [], source(), 'session-1', session_key='key', event_message_id='a'*64)
        assert result['final_response'] == 'private-response'
    assert [e.phase for e in route.events] == ['turn_started', 'session_resolved', 'turn_finished']
    assert route.events[-1].outcome == ('failed' if outcome == 'exception' else outcome)
    assert len({e.turn_id for e in route.events}) == 1
    assert 'private-' not in repr(route.events)

from unittest.mock import AsyncMock
from gateway.run_turn_runner import TurnRunner


def local_runner(route, *, outcome='success', post_cancel=False, queued=False):
    """Fake model worker only; real current _run_agent/_inner/_await/_queued chain."""
    runner = runner_for(route)
    runner._get_proxy_url = lambda: None
    runner._run_agent_display_settings = lambda source: SimpleNamespace(
        needs_progress_queue=False, log_mode_enabled=False, _native_slack_task_cards=False)
    runner._run_agent_bind_turn_wiring = lambda *args: {}
    runner._run_agent_start_streaming_tts = lambda *args: None
    runner._run_agent_evict_on_fallback = lambda *args: None
    runner._run_agent_schedule_bubble_cleanup = lambda *args: None
    for name in ('_run_agent_stream_consumer_task', '_run_agent_track_agent',
                 '_run_agent_monitor_for_interrupt', '_run_agent_notify_long_running',
                 '_run_agent_mark_streamed_delivery', '_refresh_agent_cache_message_count',
                 '_run_agent_deliver_first_response'):
        setattr(runner, name, AsyncMock())
    contexts=[]
    def build(disp, agent_class, **kwargs):
        ctx = SimpleNamespace(**kwargs, result_holder=[None], agent_holder=[None],
            _status_thread_metadata={}, _voice_ack_guild=[None],
            stream_consumer_holder=[None], streaming_tts_consumer_holder=[None])
        contexts.append(ctx)
        return ctx, TurnRunner(runner, ctx), route
    runner._run_agent_build_turn_context = build
    def start(ctx, callback):
        async def model():
            observer = getattr(callback.__self__, '_observer', None)
            if observer is not None and observer.active:
                observer.tool_started('raw-private-id', 'terminal', {'secret':'private-args'})
                observer.tool_finished('raw-private-id', 'terminal', {}, 'private-result')
            if outcome == 'exception': raise RuntimeError('private-error')
            if outcome == 'cancelled': raise asyncio.CancelledError
            result = {'final_response': '', 'messages': [], 'completed': True,
                      'failed': outcome in {'failed', 'timed_out'}, 'media_urls':['synthetic-media']}
            ctx.result_holder[0] = result
            return result
        task = asyncio.create_task(model())
        return SimpleNamespace(executor_task=task, agent_timeout=None)
    runner._run_agent_start_turn_worker = start
    async def tts(*args):
        if post_cancel: raise asyncio.CancelledError
    runner._run_agent_finalize_streaming_tts = tts
    async def drain(*args):
        return (None, 'next') if queued and len(contexts)==1 else (None,None)
    runner._run_agent_drain_pending = drain
    async def cleanup(ctx, **tasks):
        for task in tasks.values():
            if task is not None:
                task.cancel()
                try: await task
                except asyncio.CancelledError: pass
    runner._run_agent_cleanup_turn_tasks = cleanup
    return runner, contexts

@pytest.mark.asyncio
@pytest.mark.parametrize('post_cancel', [False, True])
async def test_current_worker_media_only_latches_before_post_execution_await(post_cancel):
    route=Capture()
    runner, contexts=local_runner(route, post_cancel=post_cancel)
    if post_cancel:
        with pytest.raises(asyncio.CancelledError):
            await runner._run_agent('secret', '', [], source(), 'session-1', session_key='key')
    else:
        result=await runner._run_agent('secret', '', [], source(), 'session-1', session_key='key')
        assert result['final_response']=='' and result['media_urls']==['synthetic-media']
    terminals=[e for e in route.events if e.phase=='turn_finished']
    assert len(terminals)==1 and terminals[0].outcome=='success'
    assert [e.phase for e in route.events if e.phase.startswith('tool_')]==['tool_started','tool_finished']
    assert 'private-' not in repr(route.events)

@pytest.mark.asyncio
async def test_current_queued_followup_closes_first_turn_before_second_start():
    route=Capture()
    runner, contexts=local_runner(route, queued=True)
    result=await runner._run_agent('first', '', [], source(), 'session-1', session_key='key', is_new_session=True)
    assert len(contexts)==2
    edges=[e for e in route.events if e.phase in {'turn_started','turn_finished'}]
    assert [e.phase for e in edges]==['turn_started','turn_finished','turn_started','turn_finished']
    assert edges[0].turn_id==edges[1].turn_id and edges[2].turn_id==edges[3].turn_id
    assert edges[0].turn_id!=edges[2].turn_id
    assert [e.is_new_session for e in route.events if e.phase=='session_resolved']==[True,False]
    runner._run_agent_deliver_first_response.assert_awaited_once()
    assert result['media_urls']==['synthetic-media']


@pytest.mark.asyncio
async def test_current_watchdog_timeout_is_not_generic_failure(monkeypatch):
    import threading
    import gateway.run_turn as turn_module
    route=Capture();runner,contexts=local_runner(route)
    held=asyncio.get_running_loop().create_future()
    fired=threading.Event();fired.set()
    def worker(ctx, callback):
        ctx.tools_holder=[[]]
        return SimpleNamespace(executor_task=held,agent_timeout=60,timeout_fired=fired)
    runner._run_agent_start_turn_worker=worker
    runner._agent_activity_summary=lambda agent:{'seconds_since_activity':61}
    original_wait=asyncio.wait
    async def bounded_wait(fs,timeout=None):return await original_wait(fs,timeout=0)
    monkeypatch.setattr(turn_module.asyncio,'wait',bounded_wait)
    try:
        result=await runner._run_agent('secret','',[],source(),'s',session_key='key')
        assert result['failed'] is True
        assert [e.outcome for e in route.events if e.phase=='turn_finished']==['timed_out']
    finally:held.cancel()
