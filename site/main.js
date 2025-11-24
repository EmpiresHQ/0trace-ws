import './styles.css';

const WS_URL = __WS_URL__;

const output = document.getElementById('output');
const statusIndicator = document.getElementById('status-indicator');
const statusText = document.getElementById('status-text');
const wsHost = document.getElementById('ws-host');

let ws;
let reconnectTimeout;

const STATUS = {
  connecting: { color: 'bg-gray-500', text: 'connecting' },
  connected: { color: 'bg-green-500', text: 'connected' },
  error: { color: 'bg-red-500', text: 'error' },
  disconnected: { color: 'bg-gray-500', text: 'disconnected' }
};

function setStatus(status) {
  const s = STATUS[status];
  statusIndicator.className = `w-2 h-2 rounded-full ${s.color}`;
  statusText.textContent = s.text;
}

function addLine(html) {
  const line = document.createElement('div');
  line.className = 'py-0.5';
  line.innerHTML = html;
  output.appendChild(line);
  output.scrollTop = output.scrollHeight;
}

function connect() {
  if (reconnectTimeout) clearTimeout(reconnectTimeout);
  
  setStatus('connecting');
  wsHost.textContent = WS_URL;
  ws = new WebSocket(WS_URL);
  
  ws.onopen = () => {
    setStatus('connected');
    output.innerHTML = '';
    addLine('<span class="text-green-500">connected</span>');
  };
  
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      
      switch(data.type) {
        case 'hop':
          addLine(`<span class="text-blue-400">[${data.ttl}]</span> <span class="text-gray-300">${data.ip}</span> <span class="text-purple-400">${data.rtt_ms.toFixed(2)}ms</span>`);
          break;
        case 'client_connected':
          addLine(`<span class="text-green-500">→ ${data.client_id}</span>`);
          break;
        case 'client_done':
          addLine(`<span class="text-gray-500">✓ ${data.client_id}</span>`);
          break;
        case 'error':
          addLine(`<span class="text-red-500">✗ ${data.message}</span>`);
          break;
        default:
          addLine(`<span class="text-gray-600">${JSON.stringify(data)}</span>`);
      }
    } catch (err) {
      console.error('parse error:', err);
    }
  };
  
  ws.onerror = () => {
    setStatus('error');
    addLine('<span class="text-red-500">connection error</span>');
  };
  
  ws.onclose = () => {
    setStatus('disconnected');
    addLine('<span class="text-gray-500">reconnecting in 3s...</span>');
    reconnectTimeout = setTimeout(connect, 3000);
  };
}

connect();

window.addEventListener('beforeunload', () => {
  if (ws) ws.close();
  if (reconnectTimeout) clearTimeout(reconnectTimeout);
});
