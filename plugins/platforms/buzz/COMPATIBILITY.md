# BuzzLink for Hermes compatibility

**Full Hermes agents, native on Buzz.**

BuzzLink is a native Hermes platform plugin. It connects Buzz to the complete
Hermes Agent Gateway; it does not replace Hermes with a reduced worker or
remove models, tools, memory, skills, cron, delegation, permissions, or
sessions.

## Version 0.1 host

Version 0.1 targets the tested Peakhunter Hermes integration line first. The
plugin keeps the stable Gateway platform identifier `buzz` and the existing
`BUZZ_*` configuration keys.

Bundled discovery intentionally derives that Gateway id from the plugin
directory basename (`plugins/platforms/buzz`), independently of the branded
manifest name `hermes-buzzlink`. Operators upgrading from the legacy
`buzz-platform` identity must migrate `plugins.enabled`, `plugins.disabled`,
and the `plugins.entries.buzz-platform` mapping key to `hermes-buzzlink`; the
`gateway.platforms.buzz` key remains unchanged. Repository-subdirectory
installations require a force reinstall because their installed copy has no
`.git` metadata for the normal plugin update path.

The tested host supplies two generic platform contracts used for live access
policy:

- `authorization_config_fn`
- `authorization_user_normalizer`

They let Hermes resolve saved policy on every authorization decision instead
of freezing it when the adapter starts. This is what allows access-policy
changes to apply immediately without restarting the Gateway.

## Unmodified upstream Hermes

The package installer can install BuzzLink from a repository subdirectory on
unmodified Hermes. At the time of the version 0.1 compatibility probe, however,
the upstream `PlatformEntry` contract did not expose the two live authorization
hooks above. Registration failed closed with an unsupported-keyword error; the
plugin did not start with frozen or stale access policy.

This is classified as a **proved missing generic Hermes interface**, not a Buzz
protocol change and not a reason to monkey-patch Hermes internals. All other
platform registration fields used by BuzzLink were accepted by the upstream
contract in the same probe.

## Implemented capability areas

The Peakhunter host and BuzzLink adapter currently cover:

- Gateway setup, status, and native plugin registration;
- rooms, DMs, threads, replies, mentions, and thread continuity;
- live mention and access-policy changes;
- protected Buzz media intake;
- channel discovery and remote-agent directory publication;
- cron and standalone delivery;
- structured activity publication;
- Dashboard-backed configuration supplied by the host integration.

Each release must verify these behaviors with the focused Buzz test suite and a
separate candidate identity before it replaces any live Gateway deployment.

## Current gap classification

| Area | Classification | State |
| --- | --- | --- |
| Package identity and subdirectory installation | Plugin implementation | Implemented and tested |
| Live saved access policy on Peakhunter Hermes | Existing Hermes interface used correctly | Implemented and tested |
| Live saved access policy on unmodified upstream | Proved missing generic Hermes interface | Requires the two additive hooks above |
| Buzz protocol changes for the first package slice | Required Buzz-side change | None |
| Codex/API changes for the first package slice | Required Codex/API-side change | None |

Dashboard companion packaging is intentionally not a prerequisite for version
0.1. Any additional generic interface request must be backed by a failing
plugin consumer test and the smallest additive contract that fixes it.
