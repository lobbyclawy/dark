# Contributing to dark

Thank you for your interest in contributing to dark! This document provides guidelines and information for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Project Structure](#project-structure)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)

## Code of Conduct

This project follows the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct). Please be respectful and constructive in all interactions.

## Getting Started

### Prerequisites

- **Rust 1.75+** (latest stable recommended)
- **Docker & Docker Compose** (for development environment)
- **Just** (optional, for task running): `cargo install just`

### Clone and Build

```bash
git clone https://github.com/lobbyclawy/dark.git
cd dark

# Build
cargo build

# Run tests
cargo test

# Or use just
just build
just test
```

## Development Environment

### Using Docker Compose

Start the development environment with Bitcoin regtest, PostgreSQL, and Redis:

```bash
# Start services
docker-compose up -d

# Or with just
just docker-up

# Generate some blocks
just btc-generate 101

# View logs
docker-compose logs -f
```

### Configuration

Copy the example config and adjust as needed:

```bash
cp config.example.toml config.toml
```

## Project Structure

```
dark/
├── src/                    # Main binary
│   └── main.rs
├── crates/                 # Workspace crates
│   ├── dark-core/          # Core business logic
│   ├── dark-bitcoin/       # Bitcoin primitives
│   ├── dark-wallet/        # BDK wallet service
│   ├── dark-api/           # gRPC/REST API
│   └── dark-db/            # Database layer
├── proto/                  # Protocol Buffers definitions
├── migrations/             # SQL migrations
├── tests/                  # Integration tests
├── config.example.toml     # Example configuration
└── docker-compose.yml      # Development environment
```

## Coding Standards

### Rust Style

We follow standard Rust conventions:

```bash
# Format code (required)
cargo fmt

# Run clippy (required, warnings are errors in CI)
cargo clippy --all-targets --all-features -- -D warnings
```

### Code Guidelines

1. **Use strong typing** - Avoid stringly-typed APIs
2. **Error handling** - Use `thiserror` for library errors, `anyhow` for application code
3. **Documentation** - All public items must have rustdoc comments
4. **No unsafe code** - Unless absolutely necessary and well-documented
5. **Tests** - New features should include tests

See [`docs/conventions/`](docs/conventions/README.md) for the binding workspace
conventions (errors, tracing, repositories, null-objects, async/polling). A
fuller refresh of this document is tracked under issue #511.

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(wallet): add BDK integration
fix(bitcoin): correct fee estimation
docs(api): update gRPC documentation
test(core): add VTXO tree tests
chore(deps): update dependencies
```

## Testing

### Running Tests

```bash
# All tests
cargo test --all-features --workspace

# Specific crate
cargo test -p dark-core

# With output
cargo test -- --nocapture

# Using just
just test
just test-verbose
```

### Test Guidelines

- **Unit tests**: In `mod tests` within each file
- **Integration tests**: In `tests/` directory
- **Property tests**: Use `proptest` for edge cases
- **Bitcoin tests**: Use regtest via Docker

## Pull Request Process

### Before Submitting

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feat/my-feature`
3. **Make your changes**
4. **Run CI checks locally**:
   ```bash
   just ci
   # Or manually:
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo test
   ```
5. **Commit with a descriptive message**

### Submitting

1. **Push to your fork**
2. **Open a Pull Request** against `main`
3. **Fill out the PR template**
4. **Wait for review**

### Review Process

- At least one maintainer approval required
- All CI checks must pass
- Squash commits before merging (maintainer will do this)

## Issue Reporting

### Bug Reports

Include:
- **Description**: What happened vs. what you expected
- **Steps to reproduce**
- **Environment**: OS, Rust version, etc.
- **Logs/Output**: Relevant error messages

### Feature Requests

Include:
- **Use case**: Why is this needed?
- **Proposed solution**: How should it work?
- **Alternatives considered**: Other approaches?

## Questions?

- Open a [Discussion](https://github.com/lobbyclawy/dark/discussions)
- Check existing [Issues](https://github.com/lobbyclawy/dark/issues)

---

Thank you for contributing to dark! 🚀
