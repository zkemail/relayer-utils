# Development Setup Guide

## Prerequisites

- [Rust](https://rustup.rs/)
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)
- [Bun](https://bun.sh/) (or Node.js)

## Initial Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd relayer-utils
```

2. Install dependencies:
```bash
bun install
```

3. Build WebAssembly:
```bash
bun run build
```

## Running Tests

### TypeScript Tests

```bash
# Run all tests
bun test

# Run specific test file
bun test circuit_input
```

### Rust Tests

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_name
```

## Project Structure

- `src/` - Rust source code
- `ts_tests/` - TypeScript tests
- `pkg/` - Generated WebAssembly output (created after build)
- `tests/fixtures/` - Test fixtures and sample data

## Common Issues

1. **WebAssembly Build Issues**
   - If you get module import errors, try rebuilding the WebAssembly:
   ```bash
   bun run build
   ```

2. **Test File Collisions**
   - Tests use a shared initialization module to prevent WebAssembly init collisions
   - See `ts_tests/setup.ts` for implementation

## Development Workflow

1. Make changes to Rust code
2. Rebuild WebAssembly: `bun run build`
3. Run tests to verify changes
4. Commit changes

## Test Fixtures

Place test fixtures in:
- `tests/fixtures/test.eml` - Public test emails
- `tests/fixtures/confidential/` - Private/confidential test emails 