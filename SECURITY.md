# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Threat Model

### In Scope

- Implementation correctness relative to specifications (RFCs, FIPS standards)
- Memory safety violations (buffer overflows, use-after-free, etc.)
- Timing side-channel vulnerabilities in constant-time operations
- Cryptographic weaknesses in algorithm implementation
- Zeroization failures (sensitive data leakage)
- SPARK contract violations

### Out of Scope

- Weak user-chosen secrets (passwords, keys)
- Physical attacks (side-channel power analysis, EM emissions)
- Operating system vulnerabilities
- Compiler vulnerabilities
- Hardware vulnerabilities (Spectre, Meltdown, etc.)

## Security Properties

### Memory Safety

All code is written in SPARK Ada with contracts verified by GNATprove. This provides mathematical proof of:

- No buffer overflows or underflows
- No null pointer dereferences
- No use-after-free errors
- No integer overflow in critical paths
- Correct initialization of all variables

### Side-Channel Resistance

Where applicable, implementations provide:

- **Data-independent control flow**: No conditional branches based on secret data
- **Data-independent memory access**: No secret-dependent array indexing
- **Constant-time comparisons**: Timing-independent equality checks
- **Zeroization**: Cryptographic erasure of intermediate sensitive values

### Limitations

- **Cache timing**: Not defended against CPU cache timing attacks
- **Speculative execution**: Not hardened against Spectre-class attacks
- **Power analysis**: No countermeasures for DPA/SPA
- **Fault injection**: No detection or mitigation of physical fault attacks

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to:

**sic.tau@pm.me**

### What to Include

1. Description of the vulnerability
2. Steps to reproduce
3. Proof-of-concept code (if applicable)
4. Impact assessment
5. Suggested fix (if available)

### Response Timeline

- **Initial response**: Within 7 days
- **Vulnerability assessment**: Within 14 days
- **Fix development**: Depends on severity and complexity
- **Public disclosure**: After fix is available or 90 days, whichever comes first

### Disclosure Policy

We follow coordinated vulnerability disclosure:

1. Reporter submits vulnerability privately
2. We confirm and assess severity
3. We develop and test a fix
4. We release patched version
5. We publish security advisory
6. Reporter may publish details after advisory

### Recognition

Security researchers who responsibly disclose vulnerabilities will be acknowledged in:

- Repository SECURITY.md
- Release notes for patched version
- Git commit messages (unless anonymity requested)

Thank you for improving the security of this project.
