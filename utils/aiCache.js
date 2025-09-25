// Simple in-memory TTL cache for AI results (summary & suggestions)
// Not production-grade (no clustering) but fine for MVP

const store = new Map(); // key -> { value, expires }

function set(key, value, ttlMs) {
    store.set(key, { value, expires: Date.now() + ttlMs });
}

function get(key) {
    const entry = store.get(key);
    if (!entry) return undefined;
    if (Date.now() > entry.expires) {
        store.delete(key);
        return undefined;
    }
    return entry.value;
}

function del(key) { store.delete(key); }

module.exports = { set, get, del };
