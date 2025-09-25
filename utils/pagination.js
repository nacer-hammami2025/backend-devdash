// Simple pagination helper
// parsePagination(req.query) -> { page, limit, skip }
// buildMeta({ page, limit, total }) -> { page, limit, total, totalPages, hasMore }

function parsePagination(query) {
    let page = parseInt(query.page, 10);
    let limit = parseInt(query.limit, 10);
    if (isNaN(page) || page < 1) page = 1;
    if (isNaN(limit) || limit < 1 || limit > 100) limit = 20; // cap to 100
    const skip = (page - 1) * limit;
    return { page, limit, skip };
}

function buildMeta({ page, limit, total }) {
    const totalPages = Math.ceil(total / limit) || 1;
    return {
        page,
        limit,
        total,
        totalPages,
        hasMore: page < totalPages
    };
}

module.exports = { parsePagination, buildMeta };