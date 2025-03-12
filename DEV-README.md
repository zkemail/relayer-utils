# Development Setup Guide

## Prerequisites

- [Rust](https://rustup.rs/)
- [Bun](https://bun.sh/) (or Node.js) - since we use Bun for testing we recommend using Bun for development

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
This will build the WebAssembly module and copy it to the `pkg` directory.

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

## Technical Details

### Project Architecture

This project is built as a Rust library that:
1. Compiles to WebAssembly for browser/Node.js usage
2. Uses wasm-bindgen for Rust/JS interop
3. Implements email parsing and DKIM verification
4. Provides regex pattern matching capabilities

### Key Components

- **Email Parsing**: Uses `mailparse` crate for RFC-compliant email parsing
- **DKIM Verification**: Implements DKIM signature verification
- **WebAssembly Bridge**: Uses wasm-bindgen for TypeScript/JavaScript integration
- **Regex Processing**: Supports complex pattern matching on email contents

### Build Process

The project uses:
- `wasm-pack` for WebAssembly compilation
- TypeScript for type definitions and tests
- Bun for running tests and managing dependencies

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