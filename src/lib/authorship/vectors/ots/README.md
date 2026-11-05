# OpenTimestamps test vectors (Phase 2 step 2) — do not regenerate

- `hello-world.txt(.ots)`, `incomplete.txt(.ots)`: the official samples from
  github.com/opentimestamps/opentimestamps-client/tree/master/examples (anchored in Bitcoin block 358391; pending).
- `incomplete-upgraded.txt.ots`: `incomplete.txt.ots` upgraded by OUR client against alice.btc.calendar on Nov 4 2026
  → Bitcoin block 428648. The official `ots info` (v0.8.0) reads it.
- `maya-seal.json` + `maya-seal.ots`: a real seal from Maya Test, stamped by OUR client on Nov 4 2026 at
  alice/bob (opentimestamps.org) + finney (eternitywall). Pending. `ots --no-bitcoin verify` on the statement bytes
  (JCS of `statement`) reports all three calendars pending.

Merkle roots checked against mempool.space on Nov 4 2026:
- 358391: `8a1b66ecb7cbd07d8139a7e7d7f2c41aab1f5009b8364aaf61d03ad245e47e00`
- 428648: `078cdde9c89f2e3c58c96b1658627fd9298c63c6618954ea24ac3b5a13fe18da`
- `maya-seal-anchored.ots`: `maya-seal.ots` upgraded by OUR client on Nov 5 2026 → alice: Bitcoin block 974611
  (2026-11-05T01:29:32Z), finney: block 974617 (03:31:45Z); bob still pending. The first real Story Town seal in Bitcoin.
  - 974611: `3eda31a88f410386502e73e318b3c2f92f5614cba3be35b41cb2967a074c9637` (mempool.space + blockstream.info agree)
  - 974617: `9cad0a051dbd3c6aa47c4f6410416f7ad033bcb56855a7eda918c9d2720f56ce` (mempool.space + blockstream.info agree)
