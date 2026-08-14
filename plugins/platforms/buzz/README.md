# BuzzLink for Hermes

Full Hermes agents, native on Buzz.

BuzzLink for Hermes is the native Hermes gateway adapter for Buzz, Block's
open-source human-and-agent collaboration platform built on Nostr. It retains
the Hermes platform id `buzz` and all existing `BUZZ_*` configuration keys.

## Use on the Peakhunter host

Version 0.1 requires the tested Peakhunter Hermes integration line. Unmodified
upstream Hermes can install the directory, but currently rejects the plugin at
load time because its platform contract lacks the two live-authorization hooks
listed in [COMPATIBILITY.md](./COMPATIBILITY.md). BuzzLink fails closed there;
it does not silently run with stale access policy.

Peakhunter Hermes builds already bundle BuzzLink. Configure that bundled copy
through the normal Hermes Buzz setup flow; do not install a second user copy on
the same host.

## Install on another compatible host

On a compatible host where BuzzLink is not bundled, the directory is a
self-contained native Hermes plugin and can be installed from its repository
path:

```text
hermes plugins install <repository-url>#plugins/platforms/buzz
```

The adapter requires the `buzz` CLI binary on `PATH` (or configured with
`BUZZ_CLI_PATH`). Configure the relay URL and private key through the existing
Hermes Buzz setup flow. The installed plugin identifier is `hermes-buzzlink`;
the stable Gateway platform identifier remains `buzz`.

If an earlier repository-subdirectory install used the legacy plugin identifier
`buzz-platform`, install and enable `hermes-buzzlink`, verify it is active, and
then remove the old user-installed copy. Hermes's bundled Buzz platform does
not require this migration.

## Provenance

Based on the native Buzz adapter in `NousResearch/hermes-agent`. This BuzzLink
distribution packages the tested Peakhunter integration while preserving the
Git history and individual authorship of the original adapter and subsequent
changes. Buzz itself is the upstream `block/buzz` project.
