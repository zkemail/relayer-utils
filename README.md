# Relayer Utils

A utility package for ZK email relayer operations.

## Installation

You can install the package using npm or any other package manager:

```sh
npm install @zk-email/relayer-utils
```

Or using yarn:

```sh
yarn add @zk-email/relayer-utils
```

Or using Bun:

```sh
bun add @zk-email/relayer-utils
```

## Usage Example

```javascript
import { init, parseEmail } from '@zk-email/relayer-utils';

await init();

const email = await parseEmail(emailString);
```

## Development

For development setup, building from source, and contributing to this package, please refer to our [Development Guide](./DEV-README.md).

## Learn More

To learn more about:
- Rust: see the [Rust documentation](https://www.rust-lang.org)
- Node: see the [Node documentation](https://nodejs.org)
- Bun: see the [Bun documentation](https://bun.sh)
