// Centralized error classes & helpers

class AppError extends Error {
    constructor({ code, message, status = 400, details }) {
        super(message);
        this.name = 'AppError';
        this.code = code;
        this.status = status;
        if (details !== undefined) this.details = details;
        Error.captureStackTrace?.(this, AppError);
    }
}

function badRequest(message = 'Bad request', details) {
    return new AppError({ code: 'BAD_REQUEST', message, status: 400, details });
}
function unauthorized(message = 'Unauthorized', details) {
    return new AppError({ code: 'UNAUTHORIZED', message, status: 401, details });
}
function forbidden(message = 'Forbidden', details) {
    return new AppError({ code: 'FORBIDDEN', message, status: 403, details });
}
function notFound(message = 'Not found', details) {
    return new AppError({ code: 'NOT_FOUND', message, status: 404, details });
}
function conflict(message = 'Conflict', details) {
    return new AppError({ code: 'CONFLICT', message, status: 409, details });
}
function internal(message = 'Internal server error', details) {
    return new AppError({ code: 'INTERNAL_ERROR', message, status: 500, details });
}

module.exports = { AppError, badRequest, unauthorized, forbidden, notFound, conflict, internal };
