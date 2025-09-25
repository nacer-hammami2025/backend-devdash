const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');
const { validate } = require('../middleware/validate.js');
const { success, error } = require('../utils/apiResponse.js');
const { AIAnalyzeCommentBody } = require('../docs/openapi.js');
const { generateProjectSummary, generateTaskSuggestions, analyzeComment } = require('../services/aiService');
const aiRateLimit = require('../middleware/aiRateLimit');
const checkRole = require('../middleware/checkRole');
const cache = require('../utils/aiCache');
// removed duplicate import of success
let metrics;
try { metrics = require('../metrics'); } catch (_) { /* metrics optional */ }

// Config TTL (ms)
const SUMMARY_TTL = parseInt(process.env.AI_SUMMARY_TTL_MS || '7200000', 10); // 2h
const SUGGEST_TTL = parseInt(process.env.AI_SUGGEST_TTL_MS || '3600000', 10); // 1h

// Generate project summary
const summaryHandler = async (req, res, next) => {
    try {
        const key = `summary:${req.params.projectId}`;
        let doc = cache.get(key);
        if (!doc) {
            if (req.aiMetrics) req.aiMetrics.cacheMiss();
            doc = await generateProjectSummary(req.params.projectId);
            cache.set(key, doc, SUMMARY_TTL);
            if (req.aiMetrics) req.aiMetrics.cacheSet();
        }
        else if (req.aiMetrics) req.aiMetrics.cacheHit();
        return res.json(success(doc));
    } catch (e) { return next(e); }
};
router.post('/projects/:projectId/summary', auth, checkRole('admin', 'manager'), aiRateLimit, metrics ? metrics.withAIMetrics('summary', summaryHandler) : summaryHandler);

// Generate task suggestions
const suggestionsHandler = async (req, res, next) => {
    try {
        const key = `suggest:${req.params.projectId}`;
        let doc = cache.get(key);
        if (!doc) {
            if (req.aiMetrics) req.aiMetrics.cacheMiss();
            doc = await generateTaskSuggestions(req.params.projectId);
            cache.set(key, doc, SUGGEST_TTL);
            if (req.aiMetrics) req.aiMetrics.cacheSet();
        }
        else if (req.aiMetrics) req.aiMetrics.cacheHit();
        return res.json(success(doc));
    } catch (e) { return next(e); }
};
router.post('/projects/:projectId/suggestions', auth, checkRole('admin', 'manager'), aiRateLimit, metrics ? metrics.withAIMetrics('suggestions', suggestionsHandler) : suggestionsHandler);

// Analyze a specific comment
const analyzeHandler = async (req, res, next) => {
    try {
        const { taskId, commentId } = req.validatedBody;
        const doc = await analyzeComment(taskId, commentId);
        return res.json(success(doc));
    } catch (e) { return next(e); }
};
router.post('/comments/analyze', auth, checkRole('admin', 'manager', 'member'), aiRateLimit, validate({ body: AIAnalyzeCommentBody }), metrics ? metrics.withAIMetrics('comment_analysis', analyzeHandler) : analyzeHandler);

// Capabilities endpoint
router.get('/capabilities', auth, async (req, res) => {
    const summaryTTL = parseInt(process.env.AI_SUMMARY_TTL_MS || '7200000', 10);
    const suggestTTL = parseInt(process.env.AI_SUGGEST_TTL_MS || '3600000', 10);
    const rateLimit = parseInt(process.env.AI_RATE_LIMIT_MAX || '20', 10);
    const windowMinutes = parseInt(process.env.AI_RATE_LIMIT_WINDOW_MIN || '60', 10);
    const aiEnabled = !!process.env.OPENAI_API_KEY;
    return res.json(success({
        aiEnabled,
        model: process.env.OPENAI_MODEL || 'gpt-4o-mini',
        summaryCacheTTLms: summaryTTL,
        suggestionsCacheTTLms: suggestTTL,
        rateLimitPerWindow: rateLimit,
        windowMinutes
    }));
});

module.exports = router;
