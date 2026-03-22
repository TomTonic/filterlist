# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability, please report it responsibly.

**Do not** open a public GitHub issue for security vulnerabilities.

Instead, email the maintainers directly with:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested fixes

## Security Design

### Input Validation
- Filter list parsing rejects rules with non-ASCII or unsupported characters
- Only DNS-safe characters (a-z, 0-9, '-', '.') are accepted in patterns
- Compile-time limits (MaxStates, timeout) prevent resource exhaustion

### Resource Limits
- DFA compilation is bounded by `max_states` and `compile_timeout`
- Pathological patterns that cause state explosion are rejected
- File watching uses debouncing to prevent rapid recompilation

### No Code Execution
- Filter list contents are never executed or evaluated as code
- Only domain pattern matching is performed
