import { startServer } from './index.js';
import type { HopEvent, ClientConnectedEvent, ClientDoneEvent, ErrorEvent } from './types.js';

const WS_PORT = Number(process.env.WS_PORT) || 8080;
const MAX_HOPS = Number(process.env.MAX_HOPS) || 30;
const TIMEOUT_MS = Number(process.env.PER_TTL_TIMEOUT_MS) || 1200;

console.log('Starting WebSocket server...');
console.log('Port:', WS_PORT);
console.log('Max hops:', MAX_HOPS);
console.log('Timeout per TTL:', TIMEOUT_MS, 'ms');

// Start WebSocket server
const wsServer = startServer({
  port: WS_PORT,
  maxHops: MAX_HOPS,
  perTtlTimeoutMs: TIMEOUT_MS
});

wsServer.on('clientConnected', (e: ClientConnectedEvent) => {
  console.log('[WS] Client connected:', e);
});

wsServer.on('hop', (h: HopEvent) => {
  console.log('[WS] Hop detected:', h);
});

wsServer.on('clientDone', (e: ClientDoneEvent) => {
  console.log('[WS] Client trace done:', e);
});

wsServer.on('error', (e: ErrorEvent) => {
  console.error('[WS] Error:', e);
});

console.log(`WebSocket server running on ws://0.0.0.0:${WS_PORT}`);

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down WebSocket server...');
  wsServer.stop();
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\nShutting down WebSocket server...');
  wsServer.stop();
  process.exit(0);
});
