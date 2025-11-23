import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { startServer } from './index.js';
import type { HopEvent, ClientConnectedEvent, ClientDoneEvent, ErrorEvent } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const HTTP_PORT = 3000;
const WS_PORT = 8080;

const publicPath = path.join(__dirname, 'public');
console.log('Serving static files from:', publicPath);

// Serve static files from 'public' directory
app.use(express.static(publicPath));

// Start HTTP server
app.listen(HTTP_PORT, () => {
  console.log(`HTTP server running on http://localhost:${HTTP_PORT}`);
  console.log(`Open http://localhost:${HTTP_PORT} in your browser to test`);
});

// Start WebSocket server
const wsServer = startServer({
  port: WS_PORT,
  maxHops: 30,
  perTtlTimeoutMs: 1200
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

console.log(`WebSocket server running on ws://localhost:${WS_PORT}`);

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down servers...');
  wsServer.stop();
  process.exit(0);
});
