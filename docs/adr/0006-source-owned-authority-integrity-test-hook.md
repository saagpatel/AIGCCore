# 0006. Source-owned authority-integrity test hook

## Status

Accepted

## Context

AIGCCore promises offline-by-default behavior, but the desktop UI previously
exposed only a static network snapshot. An external verifier could inspect the
policy and adapter types, yet it could not exercise a source-bound path from a
Tauri IPC request through the core adapter runtime to a dependency capable of
attempting a socket connection. That left the IPC-to-dependency runtime claim
untestable without patching an archived copy.

## Decision

The Tauri application now exposes its builder from a library crate so an
isolated verifier can drive the same registered IPC dispatcher as the desktop
binary. An opt-in `authority-integrity-test-hooks` Cargo feature registers one
probe command. The frontend module defines its invoke envelope separately and
is covered by its TypeScript unit test.

The probe uses the production `AdapterRuntime` loopback policy. Its adapter
records an attempt before calling `TcpStream::connect_timeout`, allowing an
isolated test to prove both that a loopback positive control reaches the socket
dependency and that malformed or non-loopback endpoints are rejected before an
attempt. Production builds do not enable or register the command.

The Rust test does not execute TypeScript. It therefore emits the narrowed
`MHAI_LP007_TAURI_IPC_TO_DEPENDENCY_PATH=PASS` result and does not claim an
end-to-end frontend `FULL_PATH`. The frontend request constructor and wrapper
remain separate, canonically run assertions under `pnpm test`.

## Consequences

The Tauri IPC-to-adapter-dependency authority path can be tested from source
without adding a production network surface. The canonical verification file
runs the feature-enabled Tauri tests explicitly. The verifier must provide an
isolated attempt log, bind only a run-owned loopback sensor, and deny other
egress. The hook demonstrates the exercised path only; it does not prove a
frontend-to-dependency path or that unexercised dependencies are network-free.

Moving the Tauri body into the library makes the dispatcher reusable while the
binary remains a thin call to `run()`.

## Alternatives Considered

Static policy inspection was rejected because it cannot prove runtime behavior.
A mocked adapter was rejected because it cannot prove a dependency attempt
sensor. Registering the probe in production was rejected because it would add
an unnecessary command and socket surface.
