// ESM wrapper for the native NAPI module
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const require = createRequire(import.meta.url);

// Load the native .node module
const native = require('./index.node');

// Re-export everything from the native module
export const { startServer, ServerHandle } = native;
export default native;
