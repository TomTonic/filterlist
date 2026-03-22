# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-03-22

### Added
- Initial release
- Filter list parsing: AdGuard, EasyList, and hosts-style formats
- DFA-based domain matching (Thompson NFA → subset construction → Hopcroft minimization)
- Hot reload via fsnotify with debouncing
- CoreDNS plugin with whitelist/blacklist support
- Block actions: NXDOMAIN, REFUSE, null IP
- CLI tool (`regfilter-check`) for validation, matching, and DOT export
- Prometheus metrics
- Comprehensive test suite with fuzzing support
