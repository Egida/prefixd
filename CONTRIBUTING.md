# Contributing to prefixd

Thanks for your interest in contributing!

## Getting Started

### Prerequisites

- Rust 1.89+ (`rustup update stable`)
- Docker and Docker Compose
- PostgreSQL 14+ (or use Docker)
- protobuf compiler (`protoc`)

CI checks the locked dependency graph on Linux with Rust 1.89.0, including
development dependencies, alongside the current stable tests and lints. To
repeat the minimum-compiler checks with that toolchain installed:

```bash
cargo +1.89.0 check --locked --bins --features bgp-rustbgpd
cargo +1.89.0 check --locked --all-targets --all-features
cargo +1.89.0 check --locked --no-default-features --bins
```

The production Docker builder pins Rust 1.99.1 and its image digest in
`Dockerfile`. That build toolchain is separate from the minimum supported compiler.

### Setup

```bash
# Clone
git clone https://github.com/lance0/prefixd.git
cd prefixd

# Build
cargo build --locked

# Run tests; Docker must be available for disposable PostgreSQL fixtures
cargo test --locked --features test-utils
```

For a running controller and dashboard, follow the
[rustbgpd quickstart](docs/tutorials/quickstart.md), including its separate
prebuilt-image and source-build commands. The Compose speaker RPC endpoints are
private to the selected profile; a host `cargo run` cannot use those example
addresses unchanged.

### Running Integration Tests

The speaker scripts create and clean up their own pinned Docker fixtures. They
do not use the Compose stack or an existing router lab. Run them from the
repository root with Docker available:

```bash
# Controller tests, including disposable PostgreSQL fixtures
cargo test --locked --features test-utils

# Released rustbgpd controller and receiving-peer fixtures
scripts/test-rustbgpd.sh
PREFIXD_RUSTBGPD_TEST_VERSION=0.76.0 scripts/test-rustbgpd.sh

# GoBGP compatibility fixtures
scripts/test-gobgp.sh
```

---

## Development Workflow

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation
- `refactor/description` - Code refactoring

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add IPv6 FlowSpec support
fix: handle GoBGP reconnection correctly
docs: update deployment guide for GoBGP v4
refactor: extract guardrails into separate module
test: add integration tests for reconciliation
```

### Pull Requests

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and lints
5. Submit PR against `main`

PRs should:
- Pass CI (tests, clippy, fmt)
- Include tests for new functionality
- Update documentation if needed
- Have a clear description

---

## Code Style

### Formatting

```bash
# Format code
cargo fmt

# Check formatting
cargo fmt -- --check
```

### Linting

```bash
# Run clippy
cargo clippy --all-targets --all-features -- -D warnings
```

### Pre-commit Hooks

Optional but recommended:

```bash
# Install pre-commit
pip install pre-commit
pre-commit install

# Hooks run automatically on commit
```

---

## Project Structure

```
src/
├── alerting/      # Webhook alerting (Slack, Discord, Teams, PagerDuty, etc.)
├── api/           # HTTP handlers and routes
├── bgp/           # Speaker traits, rustbgpd and GoBGP adapters
├── config/        # YAML configuration parsing
├── db/            # PostgreSQL repository
├── domain/        # Core types (AttackEvent, Mitigation, etc.)
├── guardrails/    # Safety validation
├── observability/ # Metrics, logging
├── policy/        # Policy engine, playbooks
├── scheduler/     # Reconciliation loop
├── auth/          # Authentication (sessions, operators)
├── ws/            # WebSocket handler
├── error.rs       # Error types
├── state.rs       # Shared application state
├── lib.rs         # Public module exports
└── main.rs        # CLI and startup

tests/
├── integration_*.rs  # Integration tests (testcontainers)
└── ...

frontend/         # Next.js dashboard
docs/             # Documentation
configs/          # Example configuration files
proto/            # Speaker protobuf definitions
```

---

## Testing

### Unit Tests

```bash
# Run unit tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_name
```

### Integration Tests

```bash
# Requires Docker
cargo test --locked --features test-utils

# Owned speaker fixtures (Docker; independent of Compose)
scripts/test-rustbgpd.sh
scripts/test-gobgp.sh
```

### Test Coverage

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate coverage
cargo tarpaulin --out Html
```

---

## Documentation

### Code Comments

- Document public APIs with `///` doc comments
- Explain "why" not "what" in inline comments
- Use `// TODO:` for future work

### Markdown

- Keep docs in `docs/` directory
- Update README.md for user-facing changes
- Update CHANGELOG.md for releases

### Architecture Decision Records

We document significant design decisions in [docs/adr/](docs/adr/). When making a change that affects the system's architecture (new dependency, new pattern, structural change), add an ADR following the existing format. See [ADR README](docs/adr/README.md) for the index and template.

---

## Release Process

Releases are tagged from `main`:

```bash
# Update version in Cargo.toml
# Update CHANGELOG.md
# Commit and tag
git tag v0.14.1
git push origin v0.14.1
```

CI builds and publishes:
- GitHub Release with binaries
- Docker image to ghcr.io

---

## Getting Help

- Open an issue for bugs or feature requests
- Check existing issues before creating new ones
- Be respectful and constructive

---

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

### Dashboard checks

Use Bun 1.4.3 and Node.js 26.12.0 with the committed `frontend/bun.lock`.
Run tests with native Node.js 26.12.0; production containers build and run with Bun:

```bash
cd frontend
bun install --frozen-lockfile
bun run typecheck
bun run test
bun run build
bun audit
```

The dashboard always uses the configured API. Keep response fixtures in tests;
`NEXT_PUBLIC_MOCK_MODE` is retired. `next lint` was removed upstream; standalone
lint and automated browser CI remain frontend tooling work. Production
builds enforce TypeScript checks; `bun run typecheck` runs them independently.
