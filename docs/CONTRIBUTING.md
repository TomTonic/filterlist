# Contributing to filterlist

## Development Setup

```bash
# Clone the repository
git clone https://github.com/TomTonic/filterlist.git
cd filterlist

# Install dependencies
go mod download

# Run tests
go test ./... -count=1

# Run linter (requires golangci-lint)
golangci-lint run ./...
```

## Code Style

- Run `gofmt` and `goimports` before committing
- Follow standard Go conventions
- Use the provided `.editorconfig` for consistent formatting

## Testing

- All new code must have unit tests
- Run `go test ./... -race -count=1` to check for race conditions
- Aim for >90% coverage in core packages (`filterlist`, `automaton`, `blockloader`)
- Add benchmarks for performance-critical changes

## Commit Messages

Follow conventional commits:

```
feat: add support for new filter syntax
fix: handle empty lines in hosts files
test: add integration tests for wildcard patterns
docs: update configuration reference
```

## Pull Request Checklist

- [ ] All new code has unit tests
- [ ] `go test ./... -race` passes
- [ ] Coverage not decreased below threshold
- [ ] `golangci-lint run` passes
- [ ] Benchmarks added for performance-critical changes
- [ ] Integration test demonstrating behavior
- [ ] Documentation updated for any new behavior or config
