// Metrics registry & instruments
// Exports: register, counters, histograms, middleware helpers

const client = require('prom-client');

// Use a single global registry
const register = new client.Registry();

// Default labels (can add service name)
register.setDefaultLabels({ app: 'devdash-backend' });

// Enable collection of default Node.js metrics
client.collectDefaultMetrics({ register, prefix: 'devdash_' });

// Custom metrics
const aiRequestCounter = new client.Counter({
    name: 'devdash_ai_requests_total',
    help: 'Total AI requests by type and status',
    labelNames: ['route', 'status']
});
const aiLatencyHistogram = new client.Histogram({
    name: 'devdash_ai_latency_seconds',
    help: 'AI request latency in seconds',
    labelNames: ['route', 'status'],
    buckets: [0.1, 0.25, 0.5, 1, 2, 5, 10]
});
const aiCacheCounter = new client.Counter({
    name: 'devdash_ai_cache_events_total',
    help: 'AI cache events by type',
    labelNames: ['type'] // hit / miss / set
});

register.registerMetric(aiRequestCounter);
register.registerMetric(aiLatencyHistogram);
register.registerMetric(aiCacheCounter);

function withAIMetrics(route, handler) {
    return async (req, res, next) => {
        const end = aiLatencyHistogram.startTimer({ route });
        let status = 'success';
        let cacheHit = false;
        // Provide a way for handler to mark cache event
        req.aiMetrics = {
            cacheHit: () => { aiCacheCounter.inc({ type: 'hit' }); cacheHit = true; },
            cacheMiss: () => aiCacheCounter.inc({ type: 'miss' }),
            cacheSet: () => aiCacheCounter.inc({ type: 'set' })
        };
        try {
            await handler(req, res, function (err) {
                if (err) return next(err);
            });
            end({ route, status });
            aiRequestCounter.inc({ route, status });
            if (!cacheHit) {
                // nothing extra
            }
        } catch (e) {
            status = 'error';
            end({ route, status });
            aiRequestCounter.inc({ route, status });
            return next(e);
        }
    };
}

module.exports = {
    register,
    withAIMetrics,
    aiRequestCounter,
    aiLatencyHistogram,
    aiCacheCounter
};
