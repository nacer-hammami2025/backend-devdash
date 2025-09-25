const request = require('supertest');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

const useExternalServer = process.env.USE_RUNNING_SERVER === '1';
let base;

function makeToken(userId) {
    return jwt.sign({ id: userId, role: 'admin' }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '1h' });
}

describe('Offline Sync Batch - mixed operations ordering', () => {
    let Project; let Task; let token; let projectA; let projectB; let task1; let userId;

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

        // Seed a user directly
        const userCollection = mongoose.connection.collection('users');
        const userInsert = await userCollection.insertOne({ email: 'mixed@test.dev', password: 'x', role: 'admin' });
        userId = userInsert.insertedId;
        token = makeToken(userId);

        projectA = await Project.create({ name: 'BatchMix A' });
        projectB = await Project.create({ name: 'BatchMix B' });
        task1 = await Task.create({ title: 'Task One', project: projectA._id });
    }, 60000);

    test('applies patch + upsert create + delete + conflict in single batch', async () => {
        const staleVersion = task1.version - 1; // should cause version-mismatch
        const currentVersion = task1.version;   // valid for patch

        const ops = [
            // 1. Valid patch on task1
            { entity: 'task', op: 'patch', id: String(task1._id), version: currentVersion, data: { title: 'Task One Patched' }, clientId: 'm1' },
            // 2. Upsert new project (no id)
            { entity: 'project', op: 'upsert', data: { name: 'Created In Batch' }, clientId: 'm2' },
            // 3. Delete existing projectB
            { entity: 'project', op: 'delete', id: String(projectB._id), clientId: 'm3' },
            // 4. Conflict: stale version patch
            { entity: 'task', op: 'patch', id: String(task1._id), version: staleVersion, data: { title: 'Should Conflict' }, clientId: 'm4' },
            // 5. Unsupported entity to validate conflict classification
            { entity: 'unknown', op: 'upsert', data: { foo: 'bar' }, clientId: 'm5' }
        ];

        const res = await request(base)
            .post('/api/sync/batch')
            .set('Authorization', `Bearer ${token}`)
            .send({ operations: ops });

        expect(res.status).toBe(200);
        const { applied, conflicts } = res.body;

        // Applied assertions
        const appliedIds = applied.map(a => a.clientId);
        expect(appliedIds).toContain('m1'); // patch success
        expect(appliedIds).toContain('m2'); // project create
        expect(appliedIds).toContain('m3'); // delete

        const patchApplied = applied.find(a => a.clientId === 'm1');
        expect(patchApplied.version).toBe(currentVersion + 1);

        const deleteApplied = applied.find(a => a.clientId === 'm3');
        expect(deleteApplied.deleted).toBe(true);

        // Conflicts assertions
        const conflictIds = conflicts.map(c => c.clientId);
        expect(conflictIds).toContain('m4'); // stale version
        expect(conflictIds).toContain('m5'); // unsupported entity

        const staleConflict = conflicts.find(c => c.clientId === 'm4');
        expect(staleConflict.reason).toBe('version-mismatch');

        const unsupported = conflicts.find(c => c.clientId === 'm5');
        expect(unsupported.reason).toBe('unsupported-entity');

        // DB verification
        const refreshedTask = await Task.findById(task1._id);
        expect(refreshedTask.title).toBe('Task One Patched');

        const deletedProject = await Project.findById(projectB._id);
        expect(deletedProject).toBeNull();
    });
});
