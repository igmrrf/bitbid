# Bitbid v0.1.0 publication contract

Status: live product/release choices accepted on 2026-11-09. Canonical decision: [Choose publication channels and the release verification contract](https://github.com/igmrrf/bitbid/issues/28). This is the preparation and verification contract, not a published-release claim.

## Selected identity, channels and timing

- Canonical project identity: **Bitbid**; executable/formula `bitbid`; Rust packages `bitbid-core`, `bitbid-adapters`, `bitbid-cli`, each initially `0.1.0`.
- Canonical GitHub source/releases: [igmrrf/bitbid](https://github.com/igmrrf/bitbid). User-authorized rename from `igmrrf/clienv` is complete, retaining repository ID945458350; native origin is `git@github.com:igmrrf/bitbid.git`. No source push/release occurred. The independent web repository has no origin; pointing it at a different native tree is not part of this action.
- Prepare **all three** channels: GitHub downloadable CLI archives, crates.io packages and the `bitbid` formula in the existing owned [igmrrf/homebrew-taps](https://github.com/igmrrf/homebrew-taps), tap namespace `igmrrf/taps`.
- Prepare an independent **v0.1.0 CLI preview**. It does not wait for hosted-team application delivery and does not claim hosted-team account/vault support in the current CLI. GitHub should identify the preview status plainly; crate version remains `0.1.0`.
- Publish dependencies in order: core → adapters → CLI, with verified indexing/availability before a dependent upload. Use Cargo's supported ordering/tooling; the contract does not require a custom publisher.

Observed public crate metadata for the three exact names returned404; this is not ownership, reservation or an availability guarantee. Preparation must recheck names/permissions and stop for an actual naming decision if a conflict appears. Do not silently publish another name, namespace or registry. Do not invent npm, container, domain or extra package-manager destinations.

## Initial binary and Homebrew qualification

Required first binary targets:

| Target | Deliverable |
| --- | --- |
| `aarch64-apple-darwin` | macOS Apple Silicon tar archive |
| `x86_64-apple-darwin` | macOS Intel tar archive |
| `x86_64-unknown-linux-gnu` | Linux x86_64 tar archive with explicit runtime/library requirements |

Windows follows a separate private-storage/cleanup qualification; it is not an advertised first-release target. Musl/Linux ARM/other targets require their own selected qualification before assets/support claims. A cross-compile or a documentation table is not native install/runtime evidence.

The Homebrew formula must select exact versioned archives and final SHA256 values for qualified supported hosts; supported macOS architectures need their corresponding assets, not an ARM archive labeled universal. Prove installation and actual execution on each advertised platform/architecture. Preserve other formulas in the shared tap. All prospective packaging examples remain marked unpublished until actual post-release checks pass.

## Integrity, provenance and signing

Generate and independently verify SHA256 for every archive and a versioned checksum manifest. Generate build-provenance attestations bound to the canonical repository, workflow, source revision and final asset bytes; verify the downloaded files under the intended trust policy. Checksums establish byte equality; attestations establish build-origin evidence, not program correctness.

macOS binary publication requires Developer ID signing and Apple notarization with evidence for the final delivered executable/archive and installation path. Ad-hoc signatures, checksums and attestations do not substitute. Discover the actual signing/notarization prerequisites securely during concrete preparation; no identity/credential or successful notarization is currently established. Missing prerequisites block affected binaries rather than silently produce an unsigned supported release. Authenticated external notarization/submission must be covered by action-specific authorization when its concrete payload is ready.

Use an Apple-supported notarization submission container (ZIP/DMG/signed PKG); a tar archive is a distribution artifact, not a notarization submission format. A standalone CLI binary cannot have a ticket stapled directly to it. The final tar must carry the same notarized binary and the advertised install/Gatekeeper path must be tested; do not claim a stapled standalone executable.

## Final code and package gates

Select one immutable native source revision containing the verified desired ticket commits. Complete current Bitbid branding/canonical links. Include the already approved [wallet codec/malformed-nonce repair](https://github.com/igmrrf/bitbid/issues/32) before the preview: final malformed-wallet probes must not retain the known inherited SIGABRT. Other native extraction work is not an automatic dependency merely because it is on the roadmap.

Preparation must:

1. Add registry-compatible version requirements to local path dependencies, preserving development paths and compatibility. Inspect exact packaged contents, README/license/source inclusion and absence of local secret/data/evidence files. Reconstruct and build the packaged dependency graph in an owned environment. Do not use `--no-verify` or an altered package as proof of the actual artifact.
2. Run real Cargo package/dry-run checks where their prerequisites exist. An unpublished dependent cannot be falsely declared registry-verified; actual registry-dependent checks run after its prerequisites are published and indexed. Local workspace/path installation does not establish `cargo install --locked --version 0.1.0 bitbid-cli` from crates.io.
3. Build/package the selected target archives with their toolchains and runtime requirements; validate the actual release workflow/configuration and fixed source identity. No tag/push/workflow publication is implied by local validation.
4. Run relevant native/WASM/facade/Clippy/dependency/CI gates and actual CLI help/version/completion/noninteractive/canonical+legacy token/settings/list journeys from final source, with synthetic data and loopback RPC/IPFS only. Execute platform-specific filesystem/private-mode/signal/cleanup and package install/upgrade/rollback checks on every advertised target. Reuse applicable project probes and avoid unrelated audit scope.
5. Run actual encrypted settings completeness and unset/demo reports. Every newly required deployable setting goes into encrypted `secrets/prod.enc.yaml`, preserving current values and using disabled safe states when unavailable. Provider/signing values stay out of logs/issues/handover. Credential absence is a prerequisite, not a passing check.

Host, signing or registry limitations are recorded by exact check/target/phase. Finish all independent preparation before requesting the missing prerequisite; missing required evidence is never silently waived. Prepare concrete artifact names, hashes, source SHA, commands, targets, permissions and recovery steps for release review.

## Execution and post-release verification

Local per-ticket commits are authorized by AGENTS.md after required verification/review. Push, tags, crate upload, GitHub Release publication, tap updates and deployment remain concrete external actions requiring covering authorization. The earlier repository-rename authorization covered that rename/origin action, not arbitrary publishing.

After preparation, publish only the reviewed source/payload and chosen channels. Keep each channel's state explicit; GitHub/crates.io/Homebrew do not provide one atomic transaction.

- Confirm source revision/tag and immutable release asset identity. Fresh-download each archive, verify digest/provenance/signature/notarization as applicable, install it into a clean owned environment and execute the supported runtime matrix on the target host.
- Publish/index core, then adapters, then CLI; independently fetch and build each actual registered package, then install/run the CLI from the registry in a clean owned root.
- Update the existing tap with exact verified final archive URLs/digests; independently install/upgrade/exercise the actual formula through Homebrew. A locally edited formula is not proof of tap publication.
- Record immutable versions/URLs/digests, who executed each check, actual source/build identity and each channel's completion. Do not mark the overall release done while a required selected channel or target is unverified.

## Partial failure and recovery

Stop promotion when a required channel/target fails; retain evidence and report which artifacts are already public. Verify remote state before retrying any timeout: an upload may have succeeded. Resume only the reviewed remaining actions against the same valid immutable payload; a source/content change requires a new revision/version and renewed verification.

Do not overwrite/reuse a published crate version or silently replace bytes under an advertised immutable artifact. Package yanking, release withdrawal, tag movement, deleting assets and production rollback are separate consequential actions whose exact scope must be authorized. Prefer a documented superseding version/forward fix where publication is immutable. Homebrew recovery must preserve/restore the previously verified formula/version with an explicit reviewed update, and record the real resulting state. The preview performs no user-data migration.

## Stable acceptance

- `PUB-AC1`: selected canonical identity/resources, version and package dependency order are exact, owned/available as required, and package contents/canonical links are verified; no invented release URL or supported target.
- `PUB-AC2`: final selected source passes the relevant local/runtime matrix including nonce-abort regression, compatibility and settings gates; every advertised OS/architecture has actual target evidence.
- `PUB-AC3`: exact packaged/archived assets, digest manifest, provenance and required macOS signing/notarization are independently verified before affected promotion.
- `PUB-AC4`: post-release fresh download/registry/Homebrew install and execution demonstrate the actual selected external artifacts on required targets; all channel states and immutable evidence are recorded.
- `PUB-AC5`: concrete release and failure/recovery commands, authority/prerequisites and phase-specific checks are reviewable before external execution; no local green result is represented as an external release.

Normal preparation tickets own exact files, executable check matrices, rollback boundaries and real dependencies. The external-execution ticket waits for preparation, its final chosen code and covering authorization. This decision chooses the route; it does not grant release execution or claim release readiness.

## Actual tracker continuation

| Ticket | True prerequisites |
| --- | --- |
| [Complete current Bitbid branding and canonical repository metadata](https://github.com/igmrrf/bitbid/issues/37) | User-authorized identity/verified repository rename; independent Codinary delivery |
| [Prepare verified Bitbid v0.1.0 crates.io packages](https://github.com/igmrrf/bitbid/issues/43) | This decision, branding and approved nonce-repair ticket before final package freeze |
| [Prepare signed Bitbid archives and verified release provenance](https://github.com/igmrrf/bitbid/issues/44) | This decision, branding and nonce repair; actual target/signing prerequisites before affected promotion |
| [Prepare Bitbid Homebrew formula and installation verification](https://github.com/igmrrf/bitbid/issues/45) | This decision and qualified archive preparation |
| [Publish and independently verify Bitbid v0.1.0 across three channels](https://github.com/igmrrf/bitbid/issues/46) | All three preparation tickets, final selected code/evidence and covering external-action authorization |

Remaining checkout/Compose identity migration is the separate [Bitbid cutover decision](https://github.com/igmrrf/bitbid/issues/40); maintained product metadata does not establish completed physical/data migration.
