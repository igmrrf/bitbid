# Secret and key handling in the SSR web path

> Historical server-wallet plan. The live-agreed [hosted team application contract](team-web-execution.md)
> supersedes this server-unlock approach for the new client-encrypted team-vault product.
> Native blockchain-wallet/signing custody is separate. Preserve this document as decision provenance;
> it does not describe the shipped Yew browser-local crypto console or an implemented server.

This document records the ruling from wayfinder ticket #16: how private keys,
wallet passwords, and other secret material are handled when the shared
`bitbid-core` is driven from the Leptos SSR web app instead of the `bitbid` CLI.
It is a **planning prototype**; no code is written and no existing file is
changed. It is grounded in `docs/research/leptos-ssr-contract.md` and assumes the
`core`/`adapters` split of `docs/split-core/module-partition.md` and the
workspace topology of `docs/split-core/workspace-topology.md`.

## The constraint that drives everything

Leptos server functions are `async`, their arguments and return values must be
`serde + Send`, and their bodies run server-only. The load-bearing consequence is
that **anything placed in a `Resource` is serialized to the browser** (embedded
in the SSR HTML / hydration payload), and only serialized arguments and the
serialized `Result` cross the wire. Therefore all secret material must live
strictly server-side, inside a server-function body or server context. The v1
decision below is *stateless per-request unlock*.

## Decision (v1)

### 1. Where keys live

Exclusively on the server, in server process memory, for the duration of a single
request. Keys never enter the browser, never enter a `Resource`, and are never
returned. The only persisted key material anywhere in the system is the existing
**encrypted** wallet blob on the server filesystem, reached through the native
`Store` adapter (see §5). There is no plaintext key at rest on the web tier.

### 2. Password flow → web mapping

The browser collects the wallet password in a form and passes it as an explicit
`#[server]` function argument over HTTPS. Inside the server function the body:

- reads the server context (§3), which holds no wallet keys or passwords (though
  its Pinata JWT is itself a secret), and constructs the adapter `Host`;
- runs the synchronous core use case within `tokio::task::spawn_blocking`, so the
  blocking Argon2 KDF, `std::fs` reads, and `reqwest::blocking` calls do not stall
  a Tokio worker (per the research contract: async shell, sync body);
- zeroizes the password and the derived key when the call returns.

v1 keeps **no** server-side unlocked-session cache. Every operation that needs a
key is passed the password again and re-derives in-request. This trades UX for a
smaller secret lifecycle: no key outlives the request.

### 3. Server-context contents

Shared server state registered via `leptos_routes_with_context` (and/or Axum
`FromRef` state / `leptos_axum::extract_with_state`) holds **server-only values**:

- the store root path,
- the Pinata JWT (a bearer credential that authenticates the operator's
  Pinata/IPFS account),
- the RPC URL.

The context deliberately contains **no wallet private keys and no passwords**.
The Pinata JWT, however, **is** a secret: it lives server-side only, must never be
serialized to a `Resource`, a return value, or a client signal, and must never be
logged or echoed to the browser. Server functions read the context with
`use_context`/`expect_context`; the values are reachable only because the state is
registered server-side on the router.

### 4. What crosses the wire

Only serialized **non-secret** arguments and a **sanitized** `Result`:
identifiers, CIDs, addresses, and public metadata. Arguments may include the
password (it must transit the network — see §6); everything else is non-secret.
Return values **never** contain private keys, unsealed environment values, or
decrypted secrets. Server functions return handles and public metadata, not the
secret itself. This follows the research contract's rule that a server function's
return is "just a JSON blob" and must be sanitized.

### 5. Store

The wallet and the secret index live in the server-side `Store` (filesystem) via
`bitbid-adapters`. The browser is never used to hold keys or the secret index.
The encrypted wallet blob is the only persisted key material, and it is
encrypted at rest under the wallet password.

### 6. Threat model

- **TLS is mandatory.** The per-request password transits the network as a
  server-function argument; without TLS it is exposed. HTTPS is a hard
  requirement, not a hardening step.
- **Server functions are public HTTP endpoints.** CSRF protection and rate
  limiting apply; arguments and returns are sanitized; no secret is echoed.
- **Transient secrets.** The password and derived key are transient in memory and
  zeroized when the call returns. There is no unlocked-session state to leak
  between requests in v1.
- **Server compromise / memory disclosure** exposes keys while a request is in
  flight (and the encrypted blob plus password if the attacker also sees traffic
  or memory). This is inherent to any server-side key handling.
- **No key at rest on the web tier** beyond the encrypted wallet blob.

### 7. Interface shape

Server functions are concrete, **non-generic** `async` wrappers (the
`#[server]` boundary forbids generics) that call generic core use cases with a
`Host`. They map `core::Error` to `ServerFnError` via `Error::kind()` and
`Error::public_message()`, so internal error detail is never leaked to the
client. Argument and return types are `serde + Send`; `usize`/`isize` are avoided
in favour of `i32`/`i64`.

## AC2 — the hard rule

**No secret may appear in a `Resource`, a return value, or a client signal.**
A `Resource` serializes its value into the SSR/hydration payload, so anything
inside one is effectively public to the browser. Client signals live only in the
browser. Server-function return values cross the wire. Private keys, passwords,
derived keys, and decrypted secrets are therefore confined to server-function
bodies and server process memory, and must never be placed in any of the three.

## Alternatives considered

- **Server-side session unlock** — holding key material in server context after a
  successful unlock and reusing it across requests. Deferred: better UX (unlock
  once), but it adds an at-rest-or-in-memory key lifecycle that must be designed
  deliberately (expiry, revocation, per-session isolation, and where the cache
  lives). v1 chooses stateless per-request unlock to avoid that surface.
- **Browser-side key handling / WASM execution** — running the crypto and holding
  keys in the browser. Out of scope; deferred by the map. The shared `core` is
  kept wasm-clean where cheap, but the v1 web path does not rely on it.

## Consequences

- Every keyed operation re-runs the KDF in-request; acceptable for v1, and the
  natural place to add a bounded blocking pool / concurrency limit later.
- The server context is server-only and never serialized to the browser, so it can
  be registered broadly; it nonetheless holds a bearer credential (the Pinata
  JWT), so it must not be logged or exposed.
- Adding session unlock later is an additive change to §2/§3, not a rework of the
  wire contract.
