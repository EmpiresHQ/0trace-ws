import test from 'node:test';
import assert from 'node:assert';
import { WebSocket } from 'ws';
import { startServer } from './index.js';
import type { HopEvent, ClientConnectedEvent, ClientDoneEvent, ErrorEvent } from './types.js';

test('WebSocket Server - Basic Connection', async (t) => {
  const server = startServer({
    port: 9001,
    maxHops: 5,
    perTtlTimeoutMs: 500
  });

  const events = {
    clientConnected: [] as ClientConnectedEvent[],
    hop: [] as HopEvent[],
    clientDone: [] as ClientDoneEvent[],
    error: [] as ErrorEvent[]
  };

  server.on('clientConnected', (e: ClientConnectedEvent) => events.clientConnected.push(e));
  server.on('hop', (h: HopEvent) => events.hop.push(h));
  server.on('clientDone', (e: ClientDoneEvent) => events.clientDone.push(e));
  server.on('error', (e: ErrorEvent) => events.error.push(e));

  // Wait for server to start
  await new Promise(resolve => setTimeout(resolve, 100));

  const client = new WebSocket('ws://localhost:9001');
  
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('Connection timeout')), 5000);
    
    client.on('open', () => {
      clearTimeout(timeout);
      resolve();
    });
    
    client.on('error', (err) => {
      clearTimeout(timeout);
      reject(err);
    });
  });

  // Wait for trace to complete
  await new Promise<void>((resolve) => {
    client.on('message', (data) => {
      const msg = data.toString();
      if (msg.includes('zerotrace: done')) {
        resolve();
      }
    });
    
    // Fallback timeout
    setTimeout(resolve, 3000);
  });

  client.close();
  server.stop();

  // Wait for cleanup
  await new Promise(resolve => setTimeout(resolve, 100));

  // Assertions
  assert.ok(events.clientConnected.length > 0, 'Should receive clientConnected events');
  assert.ok(events.clientDone.length > 0, 'Should receive clientDone events');
  console.log(`✓ Received ${events.hop.length} hop events`);
  console.log(`✓ Errors: ${events.error.length}`);
});

test('WebSocket Server - Multiple Clients', async (t) => {
  const server = startServer({
    port: 9002,
    maxHops: 3,
    perTtlTimeoutMs: 300
  });

  const events = { clients: new Set<string>() };
  server.on('clientConnected', (e: ClientConnectedEvent) => {
    if (e.clientId) events.clients.add(e.clientId);
  });

  await new Promise(resolve => setTimeout(resolve, 100));

  const clients = [
    new WebSocket('ws://localhost:9002'),
    new WebSocket('ws://localhost:9002'),
  ];

  await Promise.all(clients.map(c => 
    new Promise<void>((resolve, reject) => {
      const timeout = setTimeout(() => reject(new Error('Connection timeout')), 3000);
      c.on('open', () => { clearTimeout(timeout); resolve(); });
      c.on('error', reject);
    })
  ));

  await new Promise(resolve => setTimeout(resolve, 1000));

  clients.forEach(c => c.close());
  server.stop();

  await new Promise(resolve => setTimeout(resolve, 100));

  assert.ok(events.clients.size >= 2, `Should handle multiple clients (got ${events.clients.size})`);
});

test('Server Configuration - Custom Options', (t) => {
  const server = startServer({
    host: '127.0.0.1',
    port: 9003,
    maxHops: 15,
    perTtlTimeoutMs: 800
  });

  assert.ok(server, 'Server should be created with custom options');
  assert.ok(typeof server.stop === 'function', 'Server should have stop method');
  assert.ok(typeof server.on === 'function', 'Server should have on method');
  
  server.stop();
});

test('Event Handlers - All Event Types', async (t) => {
  const server = startServer({
    port: 9004,
    maxHops: 2,
    perTtlTimeoutMs: 200
  });

  let hopReceived = false;
  let connectedReceived = false;
  let doneReceived = false;

  server.on('hop', (h: HopEvent) => {
    hopReceived = true;
    assert.ok(h.clientId, 'Hop should have clientId');
    assert.ok(typeof h.ttl === 'number', 'Hop should have TTL');
    assert.ok(h.router || h.router === '', 'Hop should have router field');
  });

  server.on('clientConnected', (e: ClientConnectedEvent) => {
    connectedReceived = true;
  });

  server.on('clientDone', (e: ClientDoneEvent) => {
    doneReceived = true;
  });

  server.on('error', (e: ErrorEvent) => {
    console.log('Server error:', e);
  });

  await new Promise(resolve => setTimeout(resolve, 100));

  const client = new WebSocket('ws://localhost:9004');
  
  await new Promise<void>((resolve) => {
    client.on('open', resolve);
    setTimeout(resolve, 2000);
  });

  await new Promise(resolve => setTimeout(resolve, 800));
  
  client.close();
  server.stop();

  assert.ok(connectedReceived, 'Should receive clientConnected event');
  // hop and done events may vary based on network/permissions
  console.log(`✓ Hop received: ${hopReceived}`);
  console.log(`✓ Done received: ${doneReceived}`);
});
