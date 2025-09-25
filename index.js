require('dotenv').config();
const express = require('express');
require('express-async-errors');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const logger = require('./utils/logger');

const app = express();

// Configure trust proxy pour correctement identifier les IPs derrière un proxy
app.set('trust proxy', ['loopback', 'linklocal', 'uniquelocal']);

// Security configuration with a relaxed CSP allowing favicon & swagger UI assets
app.use(helmet({
  crossOriginResourcePolicy: { policy: "cross-origin" },
  crossOriginOpenerPolicy: { policy: "unsafe-none" }
}));

// Custom CSP (default helmet CSP is very strict for inline swagger assets / favicon)
app.use(helmet.contentSecurityPolicy({
  useDefaults: true,
  directives: {
    "default-src": ["'self'"],
    "img-src": ["'self'", 'data:'],
    "style-src": ["'self'", "'unsafe-inline'"], // swagger ui injects inline styles
    "script-src": ["'self'", "'unsafe-inline'"], // allow swagger inline scripts
    "connect-src": ["'self'"],
    "font-src": ["'self'", 'data:']
  }
}));

// Body parsers - must be before CORS
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS configuration
const allowedOrigins = [
  'http://localhost:5173',
  'http://localhost:5174',
  'http://localhost:5175',
  'http://localhost:5176',
  'http://localhost:5177',
  'http://192.168.162.31:5173', // Allow IP address access
  'http://192.168.162.31:5174', // Allow IP address access
  'http://192.168.162.31:3000', // Additional IP ports
  'http://192.168.162.31:4000',
  'http://192.168.162.31:4001',
  'http://192.168.162.31:8080'
];
// Force development mode for CORS to ensure IP access works
const isProd = false; // Override production mode to allow flexible CORS

app.use(cors({
  origin: function (origin, callback) {
    // Allow server-to-server or curl (no Origin)
    if (!origin) return callback(null, true);

    // In development mode, allow all connections
    if (!isProd) {
      console.log('CORS: Allowing connection from origin:', origin);
      return callback(null, true);
    }

    if (allowedOrigins.includes(origin)) {
      console.log('CORS: Allowing connection from allowed origin:', origin);
      return callback(null, true);
    }

    // IP Address detection - allow any IP in development
    // Enhanced IP detection to be more permissive
    if (origin && origin.match(/^http:\/\/(\d{1,3}\.){3}\d{1,3}(:\d+)?$/)) {
      console.log('CORS: Allowing connection from IP address:', origin);
      return callback(null, true);
    }

    // Optionally allow a single explicit origin via env var (comma-separated supported)
    const extra = (process.env.CORS_ORIGIN || '').split(',').map(s => s.trim()).filter(Boolean);
    if (extra.length && extra.includes(origin)) {
      return callback(null, true);
    }

    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Origin', 'X-Requested-With', 'Content-Type', 'Accept', 'Authorization', 'X-Session-Id', 'x-session-id'],
  exposedHeaders: ['X-Session-Id', 'x-session-id'],
  preflightContinue: false,
  optionsSuccessStatus: 204,
  maxAge: 86400 // 24 hours
}));

// Logging
app.use(morgan('dev')); // Always enable logging for now

// Rate limiting (configurable) — be generous on read endpoints used during app bootstrap
const RATE_LIMIT_WINDOW_MS = parseInt(process.env.RATE_LIMIT_WINDOW_MS || String(15 * 60 * 1000), 10);
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX || '1000', 10);
const limiter = rateLimit({
  windowMs: RATE_LIMIT_WINDOW_MS,
  max: RATE_LIMIT_MAX,
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => {
    // Allow frequent low-risk reads without counting against rate limit
    if (req.method === 'GET') {
      const skipPaths = ['/2fa/status', '/auth/audit-logs', '/auth/sessions', '/events'];
      return skipPaths.some((p) => req.path && req.path.startsWith(p));
    }
    return false;
  }
});

// Apply rate limiting to all API endpoints except specific ones
app.use('/api', (req, res, next) => {
  // Skip rate limiting for SSE connections
  if (req.path === '/events') {
    return next();
  }
  limiter(req, res, next);
});

// Validation / Docs (ESM interop for our newly added modules written with ES export)
const { generateOpenAPIDocument } = require('./docs/openapi.js');
const swaggerUi = require('swagger-ui-express');

// Import routes
const testRoutes = require('./routes/test');
const projectRoutes = require('./routes/projects');
const taskRoutes = require('./routes/tasks');
const userRoutes = require('./routes/users');
const authRoutes = require('./routes/auth');
const twoFARoutes = require('./routes/2fa');
const dashboardRoutes = require('./routes/dashboard');
const analyticsRoutes = require('./routes/analytics');
const aiRoutes = require('./routes/ai');
const { router: eventsRoutes } = require('./routes/events');
// Metrics (optional)
let metrics;
if (process.env.ENABLE_METRICS === 'true') {
  metrics = require('./metrics');
}

// Special handling for health endpoint with CORS headers
app.options('/health', cors({ origin: true })); // Pre-flight for health endpoint

// Basic health check for automation/tasks with permissive CORS
app.get('/health', (req, res) => {
  // Manually set CORS headers to be permissive for health checks
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');

  res.json({ status: 'ok', service: 'devdash-api' });
});

// Mirror health under /api/health (some clients prepend /api automatically)
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'devdash-api' });
});

// Favicon handling: prevent unnecessary cross-origin favicon fetch warnings / CSP noise.
// Some browsers will attempt to fetch /favicon.ico for any contacted origin (including the API).
// We return 204 No Content quickly to avoid 404 + CSP console warnings.
app.get('/favicon.ico', (req, res) => {
  res.status(204).end();
});

app.use('/api/test', testRoutes);
app.use('/api/projects', projectRoutes);
app.use('/api/tasks', taskRoutes);
app.use('/api/users', userRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/2fa', twoFARoutes);
app.use('/api/dashboard', dashboardRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/ai', aiRoutes);
app.use('/api', eventsRoutes); // Route SSE pour les événements temps réel
if (metrics) {
  app.get('/api/metrics', async (req, res) => {
    try {
      res.set('Content-Type', metrics.register.contentType);
      res.send(await metrics.register.metrics());
    } catch (e) {
      res.status(500).send('metrics_error');
    }
  });
  console.log('📈 Metrics enabled at /api/metrics');
}

// OpenAPI / Swagger docs (generated from zod schemas) with optional protection
try {
  const openapiDoc = generateOpenAPIDocument();
  const auth = require('./middleware/auth');
  const protectDocs = process.env.EXPOSE_DOCS_PUBLIC !== 'true';
  if (protectDocs) {
    app.use('/api/docs', auth, swaggerUi.serve, swaggerUi.setup(openapiDoc, { explorer: true }));
    console.log('📘 OpenAPI docs (secured) at /api/docs (set EXPOSE_DOCS_PUBLIC=true to expose)');
  } else {
    app.use('/api/docs', swaggerUi.serve, swaggerUi.setup(openapiDoc, { explorer: true }));
    console.log('📘 OpenAPI docs (public) at /api/docs');
  }
} catch (e) {
  console.error('Failed to initialize OpenAPI docs:', e);
}

// Debug: list registered route paths after mounting
try {
  // Lister toutes les routes montées
  const routes = app._router.stack
    .filter((r) => r.route && r.route.path)
    .map((r) => r.route.path);
  if (routes && routes.length) {
    console.log('Registered direct routes:', routes);
  }

  // Lister les routes montées avec leur préfixe (pour les routeurs)
  const routePaths = [];
  const extractRoutes = (stack, basePath = '') => {
    stack.forEach(layer => {
      if (layer.route) {
        routePaths.push(basePath + layer.route.path);
      } else if (layer.name === 'router' && layer.handle.stack) {
        let newPath = basePath;
        if (layer.regexp && layer.regexp.toString().includes('api')) {
          newPath += '/api';
        }
        if (layer.regexp && layer.regexp.toString().includes('auth')) {
          newPath += '/auth';
        }
        extractRoutes(layer.handle.stack, newPath);
      }
    });
  };
  extractRoutes(app._router.stack);
  console.log('All detected routes:', routePaths);
} catch (err) {
  console.error('Failed to extract routes:', err);
}

// Unified error handler (after all routes & docs)
const { errorHandler } = require('./middleware/errorHandler.js');
app.use(errorHandler);

// Start server with port retry logic
const startServer = async (startPort) => {
  let currentPort = Number(startPort);
  const maxAttempts = 10;
  let attempt = 0;

  while (attempt < maxAttempts) {
    try {
      const server = await new Promise((resolve, reject) => {
        const srv = app.listen(currentPort)
          .once('listening', () => resolve(srv))
          .once('error', (err) => {
            if (err.code === 'EADDRINUSE') {
              resolve(false);
            } else {
              reject(err);
            }
          });
      });

      if (server) {
        console.log(`🚀 Server running on http://localhost:${currentPort}`);
        return;
      }

      console.log(`Port ${currentPort} is in use, trying next port...`);
      currentPort++;
      attempt++;
    } catch (err) {
      console.error('Server failed to start:', err);
      process.exit(1);
    }
  }

  throw new Error(`Could not find an available port after ${maxAttempts} attempts`);
};

// Database and server startup
// Support both MONGO_URI and MONGODB_URI for flexibility
const mongoUri = process.env.MONGO_URI || process.env.MONGODB_URI;
if (!mongoUri) {
  console.error('❌ Missing Mongo connection string: define MONGO_URI or MONGODB_URI in your .env');
  process.exit(1);
}

mongoose.connect(mongoUri, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(async () => {
  console.log('✅ MongoDB connected');
  mongoose.set('debug', process.env.NODE_ENV === 'development');

  try {
    console.log('Starting database seed...');
    const seed = require('./seed');
    if (typeof seed === 'function') {
      await seed();
    } else if (seed && typeof seed.default === 'function') {
      await seed.default();
    }
    console.log('✅ Database seeded successfully');
  } catch (error) {
    if (error.code === 11000) {
      console.log('⚠️ Database already seeded (skipping)');
    } else {
      console.error('Error seeding database:', error);
    }
  }

  // Prefer port 4000 (legacy expectation & Vite proxy default) unless overridden
  const PORT = Number(process.env.PORT || 4000);
  try {
    console.log(`[Startup] Attempting to start DevDash API on port ${PORT}`);
  } catch (_) { }
  await startServer(PORT);
}).catch(err => {
  console.error('Failed to connect to MongoDB:', err);
  process.exit(1);
});

// Global process-level safeguards (placed after startup chain definition)
process.on('unhandledRejection', (reason, promise) => {
  console.error('🚨 Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (err) => {
  console.error('🚨 Uncaught Exception:', err);
});
