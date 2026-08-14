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

### Migrate from `buzz-platform`

The plugin identity changed at the version 0.1 boundary; the Gateway platform
id did not. Before starting the Gateway, replace `buzz-platform` with
`hermes-buzzlink` everywhere it appears under `plugins` in
`~/.hermes/config.yaml`:

- entries in `plugins.enabled` and `plugins.disabled`;
- the mapping key `plugins.entries.buzz-platform`, which becomes
  `plugins.entries.hermes-buzzlink` while retaining its nested settings.

For an earlier repository-subdirectory installation, force reinstall from the
same repository URL after making that config migration:

```text
hermes plugins install <repository-url>#plugins/platforms/buzz --force --enable
```

Do not use `hermes plugins update` for this migration. A subdirectory install
contains the selected plugin files but no `.git` metadata, so the normal update
path cannot pull it. The force reinstall also handles the package version reset
or apparent downgrade that can occur when crossing from a legacy build to the
new `hermes-buzzlink` version line. After verifying `hermes-buzzlink` is active,
remove any remaining user-installed `buzz-platform` directory. Bundled
operators do not reinstall, but must still migrate any legacy plugin config
keys.

## Provenance

Based on the native Buzz adapter in `NousResearch/hermes-agent`. This BuzzLink
distribution packages the tested Peakhunter integration while preserving the
Git history and individual authorship of the original adapter and subsequent
changes. Buzz itself is the upstream `block/buzz` project.
