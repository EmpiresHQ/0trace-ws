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
 * @returns Promise with enriched hop data as JSON string
 */
export async function geoipMiddleware(hopData: HopEvent): Promise<string> {
  console.log(`[GeoIP Middleware] START - Processing hop data:`, JSON.stringify(hopData));
  
  const ip = hopData.router || hopData.ip;
  
  if (!ip) {
    console.log('[GeoIP Middleware] No IP found, returning original');
    return JSON.stringify(hopData);
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

  console.log(`[GeoIP Middleware] Returning enriched data as JSON string`);
  return JSON.stringify(enriched);
}
