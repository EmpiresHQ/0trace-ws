// Type definitions for zerotrace-ws native addon
export interface ServerConfig {
  host?: string;
  port: number;
  maxHops?: number;
  perTtlTimeoutMs?: number;
  middleware?: (hopData: any, next: (enrichedData: any) => void) => void | Promise<void>;
}

export interface HopEvent {
  clientId: string;
  ttl: number;
  router: string;
  ip?: string;
  rtt_ms?: number;
  hostname?: string;
}

export interface ClientConnectedEvent {
  clientId: string;
  ip?: string;
}

export interface ClientDoneEvent {
  clientId: string;
  hops?: number;
}

export interface ErrorEvent {
  message: string;
}

export interface ZeroTraceServer {
  on(event: 'hop', listener: (hop: HopEvent) => void): void;
  on(event: 'clientConnected', listener: (client: ClientConnectedEvent) => void): void;
  on(event: 'clientDone', listener: (done: ClientDoneEvent) => void): void;
  on(event: 'error', listener: (error: ErrorEvent) => void): void;
  start(): void;
  stop(): void;
}

export function start_server(config: ServerConfig): ZeroTraceServer;
