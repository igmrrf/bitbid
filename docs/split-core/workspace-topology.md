# Workspace topology and feature flags

This document records the ruling from the wayfinder topology spec (#8): how the
`core`/`adapters` split for the `bsec` CLI (to be renamed `bitbid`) is laid out
as a Cargo virtual workspace, and how native-vs-wasm gating is enforced. It is a
planning prototype; the real split is not performed here.

## Implementation status (2026-10-11)

The first bounded shared protocol/crypto extraction is now implemented in
`crates/bitbid-core`. The CLI package remains at the root and the actual Yew
browser console uses WASM through a sibling path dependency. This document's
full virtual-workspace and Leptos SSR topology remains a future proposal.
See [implemented shared protocol](implemented-shared-protocol.md).

## Target crates and names

| Crate | Kind | Package name | Import name |
|---|---|---|---|
| core | lib | `bitbid-core` | `bitbid_core` |
| adapters | lib (native only) | `bitbid-adapters` | `bitbid_adapters` |
| cli | bin | `bitbid-cli` (binary `bitbid`) | — |

## Workspace

A **virtual manifest** at the repo root: `[workspace]` with **no `[package]`**,
members `crates/*`, `resolver = "2"`. Members sit at
`crates/bitbid-core`, `crates/bitbid-adapters`, and `crates/bitbid-cli`. The
`cli` crate declares `[[bin]] name = "bitbid"`.

## Dependency edges

```
bitbid-cli ──► bitbid-adapters ──► bitbid-core
     └──────────────────────────────►  (cli may depend on core directly too)
webapp (Leptos SSR, unchanged location) ──► bitbid-core   (path dependency)
```

- `bitbid-core` depends on **neither** `bitbid-adapters` nor `bitbid-cli`.
- `bitbid-adapters` depends on `bitbid-core`; it is **native-only** and must
  never enter the `hydrate` (wasm) build.
- The web app depends on `bitbid-core` by path; it does **not** depend on
  `bitbid-adapters` or `bitbid-cli`.
- `bitbid-cli` depends on both `bitbid-adapters` and `bitbid-core`, and is the
  only place that constructs a `Host` and wires concrete adapters.

## Feature flags / native-vs-wasm gating

- **`bitbid-core` carries no `std`/`no_std` feature in this phase.** It is a
  std-based crate that is *dependency-clean*: no OS-shaped or blocking crate
  enters it (per `docs/research/deps-wasm-matrix.md`, all std crypto crates used
  compile on `wasm32-unknown-unknown`). Portability is enforced by the crate
  boundary, not by `cfg`. Revisit `no_std + alloc` only if/when a client-side
  WASM execution mode lands (deferred). Consequently the core manifest has no
  feature table and no Leptos-specific feature.
- **`bitbid-adapters` is native-only.** Its native dependencies (`reqwest`
  blocking, `dirs`, `tempfile`, `rpassword`, `libc`, …) are declared under
  `[target.'cfg(not(target_arch = "wasm32"))'.dependencies]` as
  defense-in-depth, and the CLI/web server are the only consumers.
- **The `ssr`/`hydrate` features belong to the web app, not to `bitbid-core`.**
- Adapters are gated out of wasm by *not being a dependency* of the core/web
  hydrate build, plus the target-cfg dependency section above.

## Placement and webapp consumption

- The split lives inside the `clienv` repo under `crates/`.
- The Leptos web app stays where it is and consumes the core via a path
  dependency, e.g. `bitbid-core = { path = "../../../bitsec/crates/bitbid-core" }`
  (exact relative depth is set by the web app's location and settled in
  migration, not here).
- SSR-first: the server (native) composition root builds the adapter `Host`; the
  browser/hydrate build never links adapters.

## Prototype

`prototype/split-core-skeleton/` is evolved in place to this topology: a virtual
workspace over the three `bitbid-*` members, with `bitbid-core` free of feature
flags and of any edge to adapters/cli, and `bitbid-adapters` demonstrating a
native-gated (`libc`) dependency. Bodies remain `todo!()` stubs; the real split
is out of scope here.
