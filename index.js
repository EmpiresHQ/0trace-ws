import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

// Load the native .node module
const native = require('./index.node');

// Re-export everything from the native module
export const { startServer, ServerHandle } = native;
export default native;
