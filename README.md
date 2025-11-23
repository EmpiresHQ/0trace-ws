# ZeroTrace WebSocket Server 🔍

A high-performance WebSocket server with built-in network traceroute capabilities, implemented as a Node.js native addon using Rust and NAPI.

## ⚠️ Platform Requirements

This module uses Linux-specific features (`IP_RECVERR`, `MSG_ERRQUEUE`) for ICMP packet inspection. It **only works on Linux**.

For macOS/Windows development, use the included **Dev Container** (see below).

## Features

- **Real-time Traceroute**: Traces network path to each WebSocket client
- **Low-level ICMP**: Captures Time Exceeded messages directly from kernel error queue
- **Async Architecture**: Built on Tokio for high performance
- **Event-driven API**: Subscribe to connection, hop, and completion events
- **WebSocket Protocol**: Full bidirectional communication support

## Quick Start

### On Linux

```bash
# Install dependencies
npm install

# Build native module
npm run build

# Run example server
npm run test-run
```

### On macOS/Windows (Dev Container)

1. Install [Docker Desktop](https://www.docker.com/products/docker-desktop)
2. Install VS Code [Dev Containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
3. Open Command Palette (`Cmd+Shift+P` / `Ctrl+Shift+P`)
4. Select **"Dev Containers: Reopen in Container"**
5. Wait for container to build (first time only)
6. Run commands inside the container terminal

## API Usage

```javascript
const { start_server } = require('zerotrace-ws');

const server = start_server({
  host: '0.0.0.0',        // Optional, default: '0.0.0.0'
  port: 8080,             // Required
  maxHops: 30,            // Optional, default: 30
  perTtlTimeoutMs: 1200,  // Optional, default: 1200
});

// Listen to events
server.on('clientConnected', (event) => {
  console.log('Client connected:', event.clientId);
});

server.on('hop', (hop) => {
  console.log(`Hop ${hop.ttl}: ${hop.router} (${hop.rttMs.toFixed(2)}ms)`);
});

server.on('clientDone', (event) => {
  console.log('Client trace completed:', event.clientId);
});

server.on('error', (error) => {
  console.error('Error:', error.message);
});

// Stop server
server.stop();
```

## Testing

```bash
# Run Node.js tests (requires built module)
npm test

# Run Rust unit tests
cargo test

# Run example server
npm run test-run
```

## Development

### Dev Container Setup

This project includes a complete development container configuration for running on macOS/Windows.

See `.devcontainer/README.md` for details.

### Build Commands

```bash
# Debug build (faster compilation)
npm run dev

# Release build (optimized)
npm run build

# Check Rust code
cargo check

# Run Rust linter
cargo clippy
```

## How It Works

1. **WebSocket Handshake**: Accepts incoming WebSocket connections
2. **TTL Iteration**: For each hop (TTL 1→30):
   - Sets IP TTL on the TCP socket
   - Sends a WebSocket ping frame
   - Polls kernel error queue for ICMP Time Exceeded
   - Captures router IP from ICMP response
3. **Event Emission**: Broadcasts hop data to Node.js event listeners

## License

MIT
