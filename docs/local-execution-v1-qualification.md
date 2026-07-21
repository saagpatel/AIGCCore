# LocalExecutionBackendV1 Qualification

## Surface

The experimental qualification binary is compiled only with
`local-execution-backend-v1`:

```sh
cargo run --offline --locked \
  -p aigc_core_tauri \
  --features local-execution-backend-v1 \
  --bin aigc_local_execution_qualify -- \
  target/local-execution-v1/qualification.json
```

The command requires `/opt/homebrew/bin/docker`, the exact cached base image
declared in source, and already-enabled seccomp/cgroup enforcement. It never
pulls an image. It creates and deletes only program-labeled containers, one
program-labeled derived fixture image, and program-owned paths beneath the
receipt directory.

It is a qualification tool, not a normal application command. Do not point it
at user data, credentials, repositories, daemon sockets, or an external
destination.

## Passing evidence

A passing `AIGC_EXECUTION_RECEIPT_V1` contains:

- requested policy, effective Docker configuration, observed fixture effects,
  and exact endpoint/daemon/architecture/engine/runtime/kernel/image/profile/
  controller identities, re-read before PASS and export;
- all required positive, deliberately vulnerable, and safe negative controls;
- non-empty control-to-effect references whose flags resolve exactly, with no
  duplicate, missing, or detached effects;
- a candidate/reviewed/exported digest match, smuggling/TOCTOU controls, and
  atomic no-follow publication for both patch and receipt bytes;
- exact cleanup counts with every residue field at zero;
- five cold cached, thirty warm, and five five-second measurements;
- five batches each at concurrency 1, 2, and 4, with only the highest passing
  level claimed;
- explicit unknown and excluded claims.

The 2026-07-20 development qualification passed on Docker `29.5.2`, runc
`1.3.5`, and Linux `6.8.0-117-generic`. Measured cold-cached p95 was `422 ms`,
warm p95 `430 ms`, cleanup p95 `34 ms` with `34 ms` maximum, five-second added
overhead p95 `186 ms` (`4%`), peak total run-owned storage use `28,926 bytes`,
and concurrency `4`. All `22` required controls passed and all explicitly
queried residue counts were zero. All `70` observed effect identities were
unique and exactly covered by control evidence references. The durable receipt
SHA-256 was
`ff88e5be86a399cd79126fd7c0393c12df35fc63fb1e1e71baa9f64a2595f8c2`.
The durable reviewed patch SHA-256 was
`6420e664434b60f5fda9b9c94d642d88a57308c4e41193ac4c798477c8be7a46`.
This record is exact-run evidence and must not be treated as transferable to a
different runtime or source revision.

The complete durable artifacts are
`docs/evidence/local-execution-v1-receipt.json` and
`docs/evidence/local-execution-v1-reviewed.patch.json`. The checked-in receipt
is minified, so its byte digest intentionally differs from the pretty runtime
copy while canonical JSON comparison is identical.

## Operator interpretation

`PASS` means only that the exact synthetic fixture and recorded controls passed
on the exact recorded runtime. It does not authorize arbitrary repository
execution and does not establish hostile-workload, daemon, VM, kernel, or host
security.

If qualification fails, first verify that its exact labeled containers, images,
and runtime roots are absent. Do not install, pull, configure Docker, change a
firewall, or alter the VM to make the test pass without a separate substrate
audit and explicit approval.
