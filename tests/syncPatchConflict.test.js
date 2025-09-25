const request = require('supertest');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

let base;
const useExternalServer = process.env.USE_RUNNING_SERVER === '1';

function makeToken(userId) {
    return jwt.sign({ id: userId, role: 'admin' }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '1h' });
}

describe('Offline Sync Batch - patch operations', () => {
    let Project; let Task; let token; let project; let task; let userId;

    beforeAll(async () => {
        if (useExternalServer) {
            base = 'http://localhost:4000';
        } else {
            const { MongoMemoryServer } = require('mongodb-memory-server');
            const mongod = await MongoMemoryServer.create();
            process.env.MONGODB_URI = mongod.getUri();
            process.env.JWT_SECRET = 'test-secret';
            require('../server.js');
            base = 'http://localhost:4000';
        }

        Project = mongoose.models.Project || mongoose.model('Project');
        Task = mongoose.models.Task || mongoose.model('Task');

        // Seed a user via direct collection (User model lives inside server.js runtime)
        const userCollection = mongoose.connection.collection('users');
        const userInsert = await userCollection.insertOne({ email: 'patch@test.dev', password: 'x', role: 'admin' });
        userId = userInsert.insertedId;
        token = makeToken(userId);

        project = await Project.create({ name: 'Patch Base Project' });
        task = await Task.create({ title: 'Initial Task', project: project._id });
    }, 60000);

    test('successful patch increments version', async () => {
        const current = await Task.findById(task._id);
        const res = await request(base)
            .post('/api/sync/batch')
            .set('Authorization', `Bearer ${token}`)
            .send({ operations: [{ entity: 'task', op: 'patch', id: String(task._id), version: current.version, data: { title: 'Updated via patch' }, clientId: 'p1' }] });

        expect(res.status).toBe(200);
        const applied = res.body.applied.find(a => a.clientId === 'p1');
        expect(applied).toBeTruthy();
        expect(applied.version).toBe(current.version + 1);

        const after = await Task.findById(task._id);
        expect(after.title).toBe('Updated via patch');
    });

    test('conflict on stale version patch', async () => {
        const fresh = await Task.findById(task._id);
        const staleVersion = fresh.version - 1; // purposely behind
        const res = await request(base)
            .post('/api/sync/batch')
            .set('Authorization', `Bearer ${token}`)
            .send({ operations: [{ entity: 'task', op: 'patch', id: String(task._id), version: staleVersion, data: { title: 'Should Conflict' }, clientId: 'p2' }] });

        expect(res.status).toBe(200);
        const conflict = res.body.conflicts.find(c => c.clientId === 'p2');
        expect(conflict).toBeTruthy();
        expect(conflict.reason).toBe('version-mismatch');
    });
});
