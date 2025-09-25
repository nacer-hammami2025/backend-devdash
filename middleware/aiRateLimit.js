// Simple per-user rate limiter for AI endpoints
// Window and limits configurable via env: AI_RATE_WINDOW_MS, AI_RATE_MAX
const windowMs = parseInt(process.env.AI_RATE_WINDOW_MS || '60000', 10); // 1 min
const max = parseInt(process.env.AI_RATE_MAX || '5', 10); // 5 req/min/user

// Map<userId, { count, resetAt }>
const buckets = new Map();

module.exports = function aiRateLimit(req, res, next) {
    const userId = req.user && (req.user.id || req.user.userId);
    if (!userId) return res.status(401).json({ success: false, error: { code: 'UNAUTHORIZED', message: 'Authentication required' } });
    const now = Date.now();
    let bucket = buckets.get(userId);
    if (!bucket || bucket.resetAt < now) {
        bucket = { count: 0, resetAt: now + windowMs };
        buckets.set(userId, bucket);
    }
    bucket.count++;
    const remaining = Math.max(0, max - bucket.count);
    res.set('X-RateLimit-Limit', String(max));
    res.set('X-RateLimit-Remaining', String(remaining));
    res.set('X-RateLimit-Reset', String(Math.ceil(bucket.resetAt / 1000)));
    if (bucket.count > max) {
        return res.status(429).json({ success: false, error: { code: 'RATE_LIMITED', message: 'AI rate limit exceeded. Retry later.' } });
    }
    return next();
};
