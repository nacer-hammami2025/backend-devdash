const { AppError } = require('../utils/errors.js');
const { error: errorResponse } = require('../utils/apiResponse.js');

// eslint-disable-next-line no-unused-vars
function errorHandler(err, req, res, next) {
    // Zod errors may have been converted earlier; any raw AppError here
    if (err instanceof AppError) {
        return res.status(err.status).json(errorResponse(err.code, err.message, err.details));
    }

    // Duplicate key / Mongo errors
    if (err && err.code && err.code === 11000) {
        return res.status(409).json(errorResponse('DUPLICATE_KEY', 'Resource already exists', { key: err.keyValue }));
    }

    // Fallback
    const status = err.status && Number.isInteger(err.status) ? err.status : 500;
    const payload = errorResponse('INTERNAL_ERROR', process.env.NODE_ENV === 'production' ? 'Internal server error' : (err.message || 'Internal error'));
    if (process.env.NODE_ENV !== 'production') {
        payload.error.stack = err.stack;
    }
    return res.status(status).json(payload);
}

module.exports = { errorHandler };
