const express = require('express');
const router = express.Router();

// Lightweight in-process subscriber list. For production / clustering, 
// an external pub/sub (Redis, NATS) would be preferable.
const sseClients = new Set(); // each entry: { id, res }
let sseClientSeq = 0;

function sseSend(res, data) {
  try {
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  } catch (e) {
    // Ignore broken pipe
  }
}

/**
 * Broadcast an event to all connected SSE clients
 * @param {Object} evt - The event to broadcast
 */
function broadcastEvent(evt) {
  const payload = { ...evt, ts: Date.now() };
  for (const client of sseClients) {
    sseSend(client.res, payload);
  }
}

/**
 * SSE endpoint for realtime updates
 */
router.get('/events', (req, res) => {
  // Set CORS headers for SSE (important for EventSource)
  // Déterminer l'origine de la requête
  const origin = req.headers.origin;
  const isProd = process.env.NODE_ENV === 'production';

  // Liste des origines autorisées (même liste que dans index.js)
  const allowedOrigins = [
    'http://localhost:5173',
    'http://localhost:5174',
    'http://localhost:5175',
    'http://localhost:5176',
    'http://localhost:5177',
    'http://192.168.162.31:5173', // Allow specific IP address access
    'http://192.168.162.31:5174'  // Allow specific IP address access
  ];

  // En développement, accepter toutes les origines
  if (!isProd) {
    if (origin) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    } else {
      res.setHeader('Access-Control-Allow-Origin', '*');
    }
  }
  // En production, vérifier les origines autorisées
  else if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  // Vérification supplémentaire pour les IP en développement
  else if (!isProd && origin && origin.match(/^http:\/\/(\d{1,3}\.){3}\d{1,3}(:\d+)?$/)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  // Sinon, refuser l'accès
  else {
    console.warn(`[SSE] Origine non autorisée: ${origin || 'aucune'}`);
    res.setHeader('Access-Control-Allow-Origin', 'null'); // Valeur qui bloquera intentionnellement la requête
  }

  // Important pour les requêtes qui contiennent des cookies ou utilisent l'authentification
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Session-Id, x-session-id');

  // Pour OPTIONS preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Set headers for SSE
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  // Ajout de headers pour améliorer la compatibilité avec les proxys
  res.setHeader('X-Accel-Buffering', 'no'); // Désactive le buffering Nginx
  res.setHeader('Transfer-Encoding', 'chunked'); // Important pour certains proxys
  res.setHeader('Keep-Alive', 'timeout=90'); // Augmente le timeout keep-alive
  res.flushHeaders();

  const clientId = ++sseClientSeq;
  const client = { id: clientId, res, ip: req.ip || 'unknown', origin: req.headers.origin || 'unknown' };
  sseClients.add(client);
  sseSend(res, { type: 'hello', clientId, serverTime: Date.now() });
  console.log(`[SSE] client connected #${clientId} from ${client.ip} (${client.origin}), total=${sseClients.size}`);

  // Envoyer un commentaire immédiatement pour aider certains proxys à établir la connexion
  res.write(': connection established\n\n');

  // Setup keepalive ping to maintain connection (every 15 seconds - fréquence augmentée)
  const pingInterval = setInterval(() => {
    try {
      // Envoyer à la fois un commentaire (compatible avec tous les proxys) et un événement ping
      res.write(': keepalive\n\n');
      sseSend(res, { type: 'ping', ts: Date.now() });
    } catch (e) {
      console.log(`[SSE] Erreur ping client #${clientId}: ${e.message || 'erreur inconnue'}`);
      clearInterval(pingInterval);
    }
  }, 15000);

  req.on('close', () => {
    clearInterval(pingInterval);
    sseClients.delete(client);
    console.log(`[SSE] client disconnected #${clientId}, total=${sseClients.size}`);
  });
});

// Export both the router and the broadcast function
module.exports = {
  router,
  broadcastEvent
};