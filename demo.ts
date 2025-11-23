import { startServer } from './index.js';
import type { HopEvent, ClientConnectedEvent, ClientDoneEvent, ErrorEvent } from './types.js';

(async () => {
  const server = startServer({
    port: 8080,
    maxHops: 30,
    perTtlTimeoutMs: 1200
  });

  server.on('clientConnected', (e: ClientConnectedEvent) => console.log('[connected]', e));
  server.on('hop', (h: HopEvent) => console.log('[hop]', h));
  server.on('clientDone', (e: ClientDoneEvent) => console.log('[done]', e));
  server.on('error', (e: ErrorEvent) => console.error('[error]', e));

  console.log('WS server on ws://0.0.0.0:8080');
  console.log('Open a browser to that URL; any client that connects will be traced.');

  // Stop after 2 minutes (demo)
  setTimeout(() => {
    server.stop();
  }, 120000);
})();
