# Spark_Crypto_Utils

Cryptographic utility functions: nonce generation, Shamir secret sharing, key wrapping, zeroization

## Overview

Collection of formally-verifiable cryptographic utilities providing secure random nonce generation, threshold cryptography via Shamir secret sharing, key wrapping, and cryptographic memory zeroization.

### Standards Compliance

- RFC 5116: Nonce-Based AEAD
- Shamir's Secret Sharing (1979)
- RFC 3394: AES Key Wrap (conceptual basis)

### Key Features

- Cryptographically secure nonce generation
- Shamir (k,n) threshold secret sharing
- Key wrapping with ChaCha20-Poly1305
- Cryptographic memory zeroization
- Constant-time operations
- Self-test framework

## Building

### Prerequisites

- GNAT FSF 13.1+ or GNAT Pro 24.0+
- GPRbuild
- Alire (recommended)
- GNATprove (optional, for formal verification)

### Build with Alire

```bash
alr build
```

### Build with GPRbuild

```bash
gprbuild -P spark_crypto_utils.gpr
```

### Formal Verification

```bash
gnatprove -P spark_crypto_utils.gpr --level=2 --timeout=60
```

## Testing

```bash
cd tests
gprbuild -P test_spark_crypto_utils.gpr
./obj/test_spark_crypto_utils
```

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md): Module structure and implementation details
- [SECURITY.md](SECURITY.md): Threat model, security properties, vulnerability reporting
- [API Reference](docs/API.md): Detailed API documentation

## Security

For security vulnerabilities, see [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Authors

AnubisQuantumCipher <sic.tau@pm.me>

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## References

See [docs/REFERENCES.md](docs/REFERENCES.md) for academic papers, RFCs, and technical standards.
