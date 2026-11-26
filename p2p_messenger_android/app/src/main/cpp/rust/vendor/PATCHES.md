# Vendored arti crates: what Typeon changed

Five arti 0.24.0 crates are vendored and patched (`[patch.crates-io]` in
`../Cargo.toml`). The full diff against the crates.io 0.24.0 sources is in
`typeon-patches.diff`. It does not include licence files, `semver.md` or
`Cargo.lock`.

Regenerate and check it after any edit under `vendor/`. Nothing else may change:

```sh
# upstream sources: ~/.cargo/registry/src/*/tor-<crate>-0.24.0, or unpack
# https://static.crates.io/crates/<crate>/<crate>-0.24.0.crate
diff -ruN -x .cargo_vcs_info.json -x .cargo-ok -x Cargo.toml.orig -x target \
  -x 'LICENSE-*' -x semver.md -x Cargo.lock <upstream>/tor-chanmgr vendor/tor-chanmgr
```

Audit, 2026-11-26. All hunks were read. Risk is about anonymity and security,
not only correctness.

| Crate / file | Change | Why | Risk |
|---|---|---|---|
| tor-chanmgr `builder.rs` | Connect timeout for a non-direct (PT) channel: 10 s → 60 s | Snowflake on a phone takes longer than 10 s. Every attempt timed out and started a new session. | Low. A dead bridge is noticed 50 s later. Direct channels still get 5 s. |
| tor-chanmgr `mgr.rs` | `PendingGuard` removes the pending channel entry when the building future is dropped | Upstream bug: a dropped build (circuit timeout above it) left the entry in the map, so no channel to that relay was ever built again. Both bridges froze. | Low. Same calls as the normal paths. Each handle is used once (`take`). **Report upstream.** |
| tor-chanmgr `event.rs`, `mgr.rs` | A success older than 60 s, followed by 6 failed channel builds, no longer counts as "handshake works". A request served by an open channel counts as a success. | With dead bridges as the only guards, upstream reported ready forever, so the bridge fallback (`tor.rs`) never moved on. | Low. Changes only bootstrap status reporting. Worst case: a false "not ready", which parks or rotates the bridge. Unit test `typeon_stale_success`. |
| tor-circmgr `timeouts/pareto.rs` | Cached circuit timeouts are dropped when netparams change | A fast Direct history set a 1-hop timeout of about 1.2 s. Over Snowflake no build ever finished, and a new session started every second. | Low. The default timeouts apply until new history exists. |
| tor-hsservice `ipt_mgr.rs` | A Good intro point that re-establishes its circuit (same relay, same keys) stays Good and stays published until it turns Faulty | Every lost intro circuit changed the set twice and re-uploaded the descriptor (LTE battery). | **Medium, availability.** While its circuit is being rebuilt, the published descriptor names an IPT that cannot introduce. Clients that pick it fail and try another. No confidentiality impact. |
| tor-hsservice `publish/reactor.rs` | No re-upload when the IPT set is unchanged (key = `Debug` of the whole set). A dirty HsDir is still retried. One re-upload timer per time period. | The IPT manager notifies on every write, changed or not. That meant about 200 KB per notification on mobile data, plus piled-up timers. | Low. The key is kept in memory only and never logged. A real change (relay, ntor key, lifetime) still uploads. |
| tor-netdir `params.rs` | `CHANNEL_PADDING_TIMEOUT_UPPER_BOUND`: 60 s → 10 min | Lets `tor.rs` `client_config` set long padding timeouts, so an idle channel does not wake the radio. | **Medium, anonymity.** Less channel padding weakens Tor's defence against netflow-record traffic analysis by an ISP. This is a deliberate battery trade-off (225-245 s idle interval), written up in SECURITY.md. |
| tor-ptmgr `managed.rs` | On reconfigure, PT processes that are no longer configured are stopped | Upstream TODO. lyrebird kept dialing the Snowflake broker after arti had parked the bridge. | Low. A PT is kept only if all its transports are still configured as managed. |
| tor-hsservice `anon_level.rs`, `keys.rs`, `ipt_set.rs`, `timeout_track.rs` | Doc typos, lifetime elision syntax | Compiler warnings | None |

## Upstream

- `mgr.rs` pending-channel leak: a real upstream bug. Report it to
  https://gitlab.torproject.org/tpo/core/arti/-/issues with the `Action::Launch`
  hunk and this repro: a circuit-build timeout drops `get_or_launch` while a
  bridge channel is pending, and that relay never gets a channel again. First
  check whether a newer arti fixed it.
- `ptmgr` reconfigure stop: fills the upstream TODO in the same place. Can be
  sent as an MR.
- Before upgrading arti, check each row: drop the patch if upstream fixed it,
  else carry it forward and regenerate `typeon-patches.diff`.
