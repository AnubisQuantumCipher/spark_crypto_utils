# Architecture: Spark_Crypto_Utils

## Overview

This document describes the module structure, design decisions, and implementation details of Spark_Crypto_Utils.

## Module Hierarchy

### Package Structure

(Package hierarchy will be documented based on actual implementation)

## Design Principles

1. **Formal Verification First**: All code written with SPARK contracts for automated proof
2. **Zero Unsafe Code**: No foreign function interfaces in core algorithm paths
3. **Explicit Security Properties**: Document constant-time guarantees, zeroization, side-channels
4. **Standards Compliance**: Strict adherence to RFC/FIPS specifications
5. **Defensive Programming**: Fail-closed semantics, explicit error handling

## Implementation Details

### Memory Management

- **Stack allocation**: Primary data structures allocated on stack
- **No dynamic allocation**: Avoids heap fragmentation and allocation failures
- **Zeroization**: Sensitive data explicitly overwritten before deallocation

### Constant-Time Operations

Where applicable:
- No data-dependent branches on secrets
- No data-dependent memory access patterns
- Bitwise operations preferred over conditional logic
- Constant-time comparison functions

### Error Handling

- **SPARK-compatible**: No exceptions in SPARK regions
- **Explicit success flags**: Boolean `Success` out parameters
- **Fail-closed**: Sensitive outputs zeroed on error paths

## Testing Strategy

1. **Unit tests**: Per-module correctness
2. **Official test vectors**: RFC/FIPS compliance validation
3. **Property tests**: Invariant checking
4. **Formal verification**: GNATprove at level 2+

## Performance Characteristics

(Performance documentation specific to implementation)

## Future Work

- Heap-based allocation for large data structures
- Additional side-channel hardening
- Extended parameter ranges
- API extensions

## References

See [docs/REFERENCES.md](docs/REFERENCES.md) for technical standards and academic references.
