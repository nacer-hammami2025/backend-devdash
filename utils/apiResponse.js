// Standardized API response helpers
// success(data, meta?) -> { success: true, data, meta? }
// error(code, message, details?, status?) -> { success: false, error: { code, message, details } }

function success(data, meta) {
    const res = { success: true, data };
    if (meta && Object.keys(meta).length) res.meta = meta;
    return res;
}

function error(code, message, details) {
    return {
        success: false,
        error: {
            code,
            message,
            ...(details !== undefined ? { details } : {})
        }
    };
}

// Helper to wrap a promise for controller usage (optional)
const wrapAsync = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

module.exports = { success, error, wrapAsync };
