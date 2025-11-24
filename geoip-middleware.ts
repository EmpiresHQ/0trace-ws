import type { HopEvent } from './types.js';

export interface EnrichedHopEvent extends HopEvent {
  geo?: {
    city?: string;
    country?: string;
    latitude?: number;
    longitude?: number;
  };
}

/**
 * GeoIP enrichment middleware
 * 
 * @param hopData - Hop data object from traceroute
 * @param next - Callback function to send enriched data back to Rust
 */
export async function geoipMiddleware(hopData: HopEvent, next: (enrichedJson: string) => void): Promise<void> {
  console.log(`[GeoIP Middleware] START - Processing hop data:`, JSON.stringify(hopData));
  
  const ip = hopData.router || hopData.ip;
  
  if (!ip) {
    console.log('[GeoIP Middleware] No IP found, returning original');
    next(JSON.stringify(hopData));
    return;
  }

  console.log(`[GeoIP Middleware] Enriching IP: ${ip}`);
  
  // Mock enrichment
  const enriched: EnrichedHopEvent = {
    ...hopData,
    geo: {
      city: 'Mock City',
      country: 'Mock Country',
      latitude: 0,
      longitude: 0,
    }
  };

  console.log(`[GeoIP Middleware] Calling next() with enriched data`);
  next(JSON.stringify(enriched));
}
