import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const HTTP_PORT = Number(process.env.HTTP_PORT) || 3000;

const publicPath = path.join(__dirname, 'public');
console.log('Starting HTTP server...');
console.log('Serving static files from:', publicPath);
console.log('Port:', HTTP_PORT);

// Serve static files from 'public' directory
app.use(express.static(publicPath));

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Start HTTP server
app.listen(HTTP_PORT, '0.0.0.0', () => {
  console.log(`HTTP server running on http://0.0.0.0:${HTTP_PORT}`);
  console.log(`Open http://localhost:${HTTP_PORT} in your browser`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\nShutting down HTTP server...');
  process.exit(0);
});

process.on('SIGTERM', () => {
  console.log('\nShutting down HTTP server...');
  process.exit(0);
});
