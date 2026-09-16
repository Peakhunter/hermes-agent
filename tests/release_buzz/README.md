# Buzz release composition gate

This inventory is a composition checkpoint, **not release acceptance**. Upstream
is v2026.9.11 at `939e45c91d751fadd94dcd1b873ac3cb44846213`. The existing cumulative
36-path candidate was three-way composed once over this commit. No new feature
ports or reconciliation of the five original Buzz adapter expectations is included.

## Run

On Linux with bubblewrap, use the repo-owned runner and a fresh output directory:

```
python3 scripts/run_release_buzz.py backend /absolute/new-evidence
python3 scripts/run_release_buzz.py frontend /absolute/new-evidence
python3 scripts/run_release_buzz.py upstream_seams /absolute/new-evidence
```

`scripts/release-buzz-tests.json` enumerates all files. Backend uses the unmodified
native `scripts/run_tests.sh` with two workers, no retries, and 90-second per-file
caps. The observer only supplies thread-observation output and unique per-file
JUnit paths. No tests are skipped or assertions changed by the harness.

### Environment contract

The checkout owns `.venv`, root/web `node_modules`, and a plain source-path `.pth`
for subprocess imports outside the checkout cwd. Python deps were provisioned by
`uv sync --frozen --python 3.11 --extra dev --extra web --extra cron --extra mcp
--no-install-project --no-build`. Frontend: `npm ci --workspace web
--include-workspace-root --ignore-scripts --no-audit --no-fund`. Upstream lockfiles
are unchanged. No project/dependency installation scripts ran. This is a test
environment, not a packaged install or deployment artifact.

The runner currently expects owned interpreter copies in sibling
`release-v2026.9.11-evidence/{python-runtime,node-runtime}`. These are runtime
prerequisites, not test-source dependencies. Repackaging/portable provisioning
belongs to the parent's later artifact gate; provision commands and copies are
recorded in that evidence directory. No live virtualenv is mounted in tests.

Source/dependencies are mounted read-only, only cache mountpoints and evidence
outputs writable. HOME, managed settings, /tmp, PID and network namespaces are
synthetic. The preflight checks blocked network and absence of live homes/runtime
and canonical projects. Empty mountpoint directories are created in this checkout.

## Inherited baseline failures (unchanged)

All in `tests/gateway/test_buzz_adapter.py`:
- `TestInboundAttachments::test_unauthorized_sender_attachment_is_not_downloaded`
- `TestMentionGating::test_require_mention_false_still_dispatches_unaddressed_message`
- `TestMentionGating::test_allowlist_blocks_unauthorized`
- `TestMentionGating::test_unknown_sender_tag_gets_no_reaction`
- `TestNip10ThreadReplyMentionGate::test_thread_reply_to_own_message_dispatches_without_mention`

These must be reconciled by the parent through actual installed-behavior tests,
not skips/xfails or weakened assertions. Baseline XML remains external immutable
evidence; production tests and expected values here were not changed.

## Carried evidence-only contracts

`tests/release_buzz/` contains the byte-preserved four-file 75-case authorization
contract set: installed contract (46), precedence matrix (8), owner probes (15),
reviewer edges (6). The former 69-case set is the first three, not another missing
suite. Original source/hash provenance is in the inventory; execution uses only
repo-owned tests. Future unimplemented directory/Activity/messaging and Config
discoverability work, broad builds, independent review and live acceptance are
explicitly outside this checkpoint.
