# ADR 0001 — Windows kernel component in C, all logic in Rust user mode

**Status:** accepted

## Context
The endpoint must intercept file I/O (minifilter), gate process creation, and strip handles to the sensor.
These require a kernel driver. Rust is preferred for memory safety. `windows-drivers-rs` supports WDM/KMDF
but minifilter (`FltMgr`) bindings and samples are immature, and driver signing/debug tooling assumes C/C++.

## Options
1. **Rust driver** via `windows-drivers-rs` + hand-written `fltKernel.h` bindings.
2. **Minimal C driver** that only intercepts and forwards fixed-size messages; every parser, model, and policy in Rust user mode.

## Decision
Option 2. The driver is a thin, auditable (~1k LoC) C module with no parsing of untrusted content. Revisit
Option 1 when `wdk` crates ship minifilter support.

## Consequences
- The kernel attack surface is small and reviewable; complex code stays memory-safe.
- Pre-exec verdicts cost a kernel→user round trip (bounded by a 200 ms fail-open timeout).
