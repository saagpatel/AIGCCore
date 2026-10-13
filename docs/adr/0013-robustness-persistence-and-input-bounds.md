# ADR 0013: Robust persistence and bounded validation

## Status

Accepted

## Decision

- Vault creation refuses any existing vault configuration or key state. Key opening follows the provider recorded with the wrapped DEK and never creates a replacement key.
- DEK rotation writes a complete new data generation and wrapped key, synchronizes the generation, and atomically publishes one active-generation pointer. A crash before pointer publication leaves the prior generation active. Retired generations are removed only after publication.
- Plaintext-mode vault data remains plaintext through rotation.
- Blob identifiers and deliverable paths are validated at their storage boundary. Existing identical deliverables may be observed without rewriting; changed bytes are rejected.
- Audit append rejects an unterminated final record. Repair is not automatic because removing or completing bytes would alter audit evidence. The complete chain is verified on open; append locks the file, validates the current tail, writes one newline-terminated record, and synchronizes it.
- Bundle validation caps ZIP size at 256 MiB, entry count at 4,096, uncompressed entry size at 64 MiB, total declared uncompressed size at 256 MiB, and compression ratio at 1,000:1 for entries over 1 KiB.
- Export working directories are scoped by an RAII guard. The finished ZIP remains at its returned output path.
- The running executable is hashed by streaming and cached for the process lifetime. Build provenance invalidates on tracked source inputs and Git revision inputs.
- Operational logging omits log message fields to avoid writing payloads or secrets; it remains separate from the evidence audit trail.

## Consequences

The active generation pointer is the vault rotation commit point. An unreferenced staged generation can be safely ignored after interruption. Audit logs without a final newline require explicit recovery outside normal open/append. ZIP bundles beyond declared bounds fail with stable limit codes before entry processing.
