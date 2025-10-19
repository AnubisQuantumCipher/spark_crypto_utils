# Contributing to spark_crypto_utils

Thank you for your interest in contributing!

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## Development Process

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/your-feature`)
3. **Implement** your changes with SPARK contracts
4. **Test** thoroughly (unit tests + formal verification)
5. **Document** all public APIs and contracts
6. **Commit** with descriptive messages
7. **Push** to your fork
8. **Submit** a pull request

## Coding Standards

### SPARK Ada Guidelines

- All code must be SPARK Ada compliant (`pragma SPARK_Mode (On)`)
- All public procedures/functions must have contracts:
  - `Pre`: Preconditions
  - `Post`: Postconditions
  - `Global`: Global variable access
  - `Depends`: Input/output dependencies
- No unsafe features (access types, exceptions in SPARK region, etc.)
- Formal verification with GNATprove must pass at level 2

### Style Guidelines

- **Indentation**: 3 spaces (standard Ada convention)
- **Line length**: Maximum 120 characters
- **Naming**:
  - Types: `Mixed_Case`
  - Variables: `Mixed_Case`
  - Constants: `Mixed_Case`
  - Procedures/Functions: `Mixed_Case`
- **Comments**: Explain *why*, not *what*. Document security properties.

### Cryptographic Guidelines

- **Cite standards**: Reference RFC/FIPS section numbers in comments
- **Document security properties**: Explain constant-time guarantees, zeroization
- **Test vectors**: Include official test vectors in test suite
- **No optimizations compromising security**: Prefer clarity and correctness over performance

## Testing Requirements

### Unit Tests

- Cover all public API functions
- Include boundary conditions
- Test error paths
- Use official test vectors where available

### Formal Verification

```bash
gnatprove -P spark_crypto_utils.gpr --level=2 --timeout=60
```

All checks must prove successfully. No unproven checks or medium/high warnings.

### Performance Tests

- Document performance characteristics
- Include benchmarks for common parameter sets
- Note: Security takes precedence over performance

## Documentation Requirements

- **Public APIs**: Full Ada specification comments
- **Security properties**: Document threat model, guarantees, limitations
- **Examples**: Provide usage examples
- **References**: Cite academic papers, RFCs, standards

## Pull Request Process

1. **Title**: Concise description (e.g., "Fix timing leak in comparison function")
2. **Description**: Explain what, why, and how
3. **Tests**: Demonstrate test coverage
4. **Verification**: Show GNATprove passes
5. **Breaking changes**: Clearly document API changes

### Review Criteria

- Correctness: Implements specification correctly
- Security: No introduced vulnerabilities
- Contracts: All SPARK contracts present and verified
- Tests: Adequate test coverage
- Documentation: Clear and complete
- Style: Follows coding standards

## Security Contributions

For security-sensitive contributions:

1. **Do not** disclose vulnerabilities publicly
2. **Contact** maintainers privately first (see SECURITY.md)
3. **Wait** for security advisory before submitting public PR
4. **Coordinate** disclosure timeline with maintainers

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
