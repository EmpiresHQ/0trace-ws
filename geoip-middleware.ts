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
 * GeoIP enrichment middleware - returns Promise<string>
 * 
 * @param hopData - Hop data JSON string from traceroute
 * @returns Promise that resolves to enriched JSON string
 */
export async function geoipMiddleware(hopDataJson: string): Promise<string> {
  console.log(`[GeoIP Middleware] START - Processing hop data:`, hopDataJson.substring(0, 100));
  
  const hopData: HopEvent = JSON.parse(hopDataJson);
  const ip = hopData.router || hopData.ip;
  
  if (!ip) {
    console.log('[GeoIP Middleware] No IP found, returning original');
    return hopDataJson;
  }

  console.log(`[GeoIP Middleware] Enriching IP: ${ip}`);
  
  // Mock enrichment (можно добавить реальный async API call)
  const enriched: EnrichedHopEvent = {
    ...hopData,
    geo: {
      city: 'Mock City',
      country: 'Mock Country',
      latitude: 0,
      longitude: 0,
    }
  };

  const result = JSON.stringify(enriched);
  console.log(`[GeoIP Middleware] Returning enriched data:`, result.substring(0, 100));
  return result;
}
