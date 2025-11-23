# Dev Container Setup

This project uses a Debian-based dev container to support Linux-only features (IP_RECVERR/MSG_ERRQUEUE for ICMP traceroute).

## Usage

1. Install the "Dev Containers" extension in VS Code
2. Open the command palette (Cmd+Shift+P)
3. Select "Dev Containers: Reopen in Container"
4. Wait for the container to build and dependencies to install

## What's Included

- Debian Bookworm base image
- Rust toolchain (latest stable)
- Node.js 22
- Build tools and dependencies
- Port 8080 forwarded for WebSocket server

## Building & Running

Inside the container:

```bash
# Build Rust code
cargo build

# Build NAPI module
npm run build

# Run the server
npm run test-run
```

## Testing

```bash
# Run Rust tests
cargo test

# Run Node.js tests
npm test
```
