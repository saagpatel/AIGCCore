# ADR 0013: Robust persistence and bounded validation

## Status

Accepted

## Decision

- Vault creation refuses any existing vault configuration or key state. Key opening follows the provider recorded with the wrapped DEK and never creates a replacement key.
- DEK rotation writes a complete new data generation and wrapped key, synchronizes the generation, and atomically publishes one active-generation pointer. A crash before pointer publication leaves the prior generation active. Retired generations are removed only after publication.
- Plaintext-mode vault data remains plaintext through rotation.
- Layout change: a vault is now a set of generations under `generations/` plus a `meta/active_generation` pointer. The earlier flat layout (data directories and `meta/key_state.json` directly under the vault root) still opens. Rotating a flat vault copies only `sqlite/`, `blobs/`, `caches/` and `meta/key_state.json` into the first generation, publishes the pointer, then removes those retired paths so the old wrapped DEK no longer unlocks stale data. `vault_config.json`, the fallback KEK and `generations/` are never copied into a generation.
- Concurrency contract: every open `VaultStorage` holds a shared OS lock on `meta/.lock`. Creation and rotation take it exclusively and fail with `VAULT_IN_USE` (rotation) or `VAULT_CREATE_IN_PROGRESS` (creation) rather than wait, so rotation cannot lose a blob written through another instance. The OS drops the lock if a process dies, so a crash never leaves a lock that blocks later work. Opening waits for a rotation in flight. The default is one rotating owner; see open question Q3.
- Blob writes go to a synced temporary file and are published with a no-replace hard link, so an interrupted write never leaves a partial blob at its final name. Stale `.partial` files are ignored by rotation.
- Once the active-generation pointer rename succeeds the publish is committed. A failed directory sync afterwards is logged, not returned, so a caller never deletes the generation the pointer names.
- IO failures in the vault, audit log and archive writer carry the operation and path (`CoreError::IoAt`).
- Blob identifiers and deliverable paths are validated at their storage boundary. Existing identical deliverables may be observed without rewriting; changed bytes are rejected.
- Audit append rejects an unterminated final record. Repair is not automatic because removing or completing bytes would alter audit evidence. The complete chain is verified on open; append locks the file, validates the current tail, writes one newline-terminated record, and synchronizes it.
- Bundle validation caps ZIP size at 256 MiB, entry count at 4,096, uncompressed entry size at 64 MiB, total uncompressed size at 256 MiB. Headers are untrusted: every entry is decompressed once, bounded by its declared size plus one byte, and rejected with `ENTRY_SIZE_MISMATCH` if it inflates past it; the running total of bytes actually produced is checked against the same cap, and compression ratio at 1,000:1 for entries over 1 KiB.
- Export working directories are scoped by an RAII guard. The finished ZIP remains at its returned output path in the system temporary directory. It is reserved with `create_new` and mode 0600 (unix) and is never opened through a symlink. Nothing removes a successfully exported ZIP: that retention gap stays until the owner decides on an export destination (Q2).
- The running executable is hashed by streaming and cached for the process lifetime. Build provenance invalidates on tracked source inputs (source directories, every `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `build.rs`, `build_provenance.rs`, `tauri.conf.json`, `capabilities/`) and Git revision inputs, and the `+DIRTY` stamp is computed over that same path set so the stamp and the rebuild triggers agree. A failed executable hash is not cached.
- Operational logging omits log message fields to avoid writing payloads or secrets; it remains separate from the evidence audit trail.

## Consequences

The active generation pointer is the vault rotation commit point. An unreferenced staged generation can be safely ignored after interruption. Audit logs without a final newline require explicit recovery outside normal open/append. ZIP bundles beyond declared bounds fail with stable limit codes before entry processing.
