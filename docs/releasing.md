---
id: releasing
title: Releasing the Cockpit build
---

# Releasing the Cockpit build

This fork (Androlax2/greyproxy) publishes the greyproxy that
[Agent Cockpit](https://github.com/Androlax2/agent-cockpit) installs. Releases are built from the
`dotfiles` branch, the upstream release plus the fork's fixes, by
`.github/workflows/cockpit-release.yml`. Upstream's own releases (`release.yml`, goreleaser) ignore
these tags.

Linux amd64 and arm64 are the required release targets for Linux and WSL2 Alpha1.
macOS delivery is deferred: no Darwin archive is built, smoke-tested, attested or published.
Ordinary developer CI remains unchanged.

## Cutting a release

1. Have the reviewed changes integrated into `dotfiles` by an authorized maintainer. Every pull request already runs the same build, the tests
   and a `greyproxy --version` smoke test on each target, without publishing anything.
2. Obtain separate exact approval for publication and a new tag; never move or reuse an existing tag.
   Preserve `v0.4.5-cockpit.2` at `50e2fff5020a232afb903155931aebfa13653797`.
   Pick the tag: `v<upstream version>-cockpit.<n>`, where the upstream version is the nearest
   GreyhavenHQ/greyproxy release in the commit's history (with upstream's tags fetched:
   `git describe --tags --abbrev=0 --exclude '*-*'`; the workflow fetches them itself) and `<n>` starts at 1 and goes up by one for each release on the same upstream version.
3. Tag the tip of `dotfiles` and push the tag:

   ```bash
   git fetch origin dotfiles
   git tag v0.4.5-cockpit.1 origin/dotfiles
   git push origin v0.4.5-cockpit.1
   ```

The workflow refuses a tag that is malformed, names another upstream version than the commit's,
or sits on a commit outside `dotfiles`. Otherwise it tests, builds, smoke-tests, attests the
Linux archives and publishes a GitHub release whose notes name the exact commit and deferred macOS status.
Publication requires successful build/tests and both Linux smoke jobs; failed, cancelled,
skipped or missing required results cannot authorize publication.

Run `python3 scripts/cockpit_release_test.py` for the offline workflow and packaging contracts.

## What a release holds

| Asset | Content |
| --- | --- |
| `greyproxy-<tag>-linux-amd64.tar.gz` | `greyproxy` and `LICENSE` |
| `greyproxy-<tag>-linux-arm64.tar.gz` | `greyproxy` and `LICENSE` |
| `SHA256SUMS` | SHA-256 of each archive |

The binaries are static (`CGO_ENABLED=0`), built with `-trimpath` by the Go toolchain that
`go.mod`'s `toolchain` line pins. The build time is the commit time and the archives have fixed
metadata, so rebuilding a commit gives the same bytes: `scripts/cockpit-release.sh <tag> <version>
dist` reproduces them on Linux (GNU tar and coreutils) with the same Go version.

`greyproxy --version` reports the plain upstream version (`0.4.5`), because greywall parses it and
treats anything else as outdated; its `commit:` line tells the fork build apart.

## How Cockpit consumes it

Cockpit pins one release: the tag, the commit, and for each target the archive URL and its
SHA-256 (from `SHA256SUMS`). It downloads the archive for the machine, checks the SHA-256,
unpacks `greyproxy`, and installs and runs the service itself; the release ships no installer.
To check provenance as well:

```bash
gh attestation verify greyproxy-v0.4.5-cockpit.1-linux-amd64.tar.gz -R Androlax2/greyproxy
```

Moving Cockpit to a new release means cutting the tag here, then updating the pin in Cockpit.
