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
 * @param next - Callback to send enriched data back: next(enrichedHopObject)
 */
export async function geoipMiddleware(hopData: HopEvent, next: (enrichedData: EnrichedHopEvent) => void): Promise<void> {
  try {
    console.log(`[GeoIP Middleware] Processing hop data...`);
    
    const ip = hopData.router || hopData.ip;
    
    if (!ip) {
      // No IP to enrich, send original data back
      next(hopData);
      return;
    }

    console.log(`[GeoIP Middleware] Enriching IP: ${ip}`);
    
    // TODO: Use actual MaxMind GeoIP2 database
    // import { Reader } from '@maxmind/geoip2-node';
    // const reader = await Reader.open('/path/to/GeoLite2-City.mmdb');
    // const response = reader.city(ip);
    
    // Mock enrichment for now
    const enriched: EnrichedHopEvent = {
      ...hopData,
      geo: {
        city: 'Mock City',
        country: 'Mock Country',
        latitude: 0,
        longitude: 0,
      }
    };

    // Example with real GeoIP (commented out):
    /*
    try {
      const response = reader.city(ip);
      enriched.geo = {
        city: response.city?.names?.en,
        country: response.country?.names?.en,
        latitude: response.location?.latitude,
        longitude: response.location?.longitude,
      };
      console.log(`[GeoIP Middleware] Found: ${enriched.geo.city}, ${enriched.geo.country}`);
    } catch (error) {
      console.error(`[GeoIP Middleware] Lookup failed for ${ip}:`, error);
    }
    */

    // Send enriched data back via next() callback
    console.log(`[GeoIP Middleware] Sending enriched data back`);
    next(enriched);
    
  } catch (error) {
    console.error('[GeoIP Middleware] Error:', error);
    // On error, send original data back
    next(hopData);
  }
}
