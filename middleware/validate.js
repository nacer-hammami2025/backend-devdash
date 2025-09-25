const { ZodError } = require('zod');
const { badRequest } = require('../utils/errors.js');

// validate({ body?, query?, params? }) returns middleware
function validate(schemas = {}) {
    return (req, res, next) => {
        try {
            if (schemas.body) {
                const parsed = schemas.body.parse(req.body);
                req.validatedBody = parsed;
            }
            if (schemas.query) {
                const parsed = schemas.query.parse(req.query);
                req.validatedQuery = parsed;
            }
            if (schemas.params) {
                const parsed = schemas.params.parse(req.params);
                req.validatedParams = parsed;
            }
            return next();
        } catch (err) {
            if (err instanceof ZodError) {
                const details = err.issues.map(i => ({ path: i.path.join('.'), message: i.message, code: i.code }));
                return next(badRequest('Validation failed', details));
            }
            return next(err);
        }
    };
}

module.exports = { validate };
