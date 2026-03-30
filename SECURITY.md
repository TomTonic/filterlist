# Security

If you find a significant vulnerability, or evidence of one,
please report it privately.

We prefer that you use the
[GitHub mechanism for privately reporting a vulnerability](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability#privately-reporting-a-security-vulnerability).
Under the
[main repository's security tab](../../security),
click "Report a vulnerability" to open the advisory form.

We will acknowledge your report within 48 hours and aim to provide a
fix or mitigation within 7 days for critical issues.

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
