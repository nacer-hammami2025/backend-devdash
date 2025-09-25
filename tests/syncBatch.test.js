const request = require('supertest');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');

// We import the compiled server entrypoint if available; fallback to server.js export adaptation would be needed.
// Assuming server.js starts the app directly, we create a lightweight express instance is not exported.
// For test simplicity we dynamically require server bootstrap via a minimal re-export wrapper if necessary.
// Here we spin up our own minimal models & reuse the same mongoose connection.

let app; // will lazy-load after setting env

// Helper to generate auth header
function makeToken(userId) {
  return jwt.sign({ id: userId, role: 'admin' }, process.env.JWT_SECRET || 'test-secret', { expiresIn: '1h' });
}

// Because current server.js does not export app, we replicate essential models used by sync logic.
// Instead, we issue HTTP calls directly to the running dev server if present (health at :4000) as a fallback.
// For isolation we implement a guarded skip.

const useExternalServer = process.env.USE_RUNNING_SERVER === '1';

describe('Offline Sync Batch Endpoint', () => {
  let Project; let Task; let userId; let token; let base;

  beforeAll(async () => {
    if (useExternalServer) {
      base = 'http://localhost:4000';
    } else {
      // Spin up in-memory mongo
      const { MongoMemoryServer } = require('mongodb-memory-server');
      const mongod = await MongoMemoryServer.create();
      process.env.MONGODB_URI = mongod.getUri();
      process.env.JWT_SECRET = 'test-secret';
      // Dynamically import server.js (it will listen). We'll interact via base URL.
      require('../server.js');
      base = 'http://localhost:4000';
    }

    // Setup direct mongoose models to create seed user & docs
    const userSchema = new mongoose.Schema({ email: String });
    const projectSchema = new mongoose.Schema({ name: String, version: { type: Number, default: 0 } }, { timestamps: true });
    const taskSchema = new mongoose.Schema({ title: String, project: mongoose.Schema.Types.ObjectId, version: { type: Number, default: 0 } }, { timestamps: true });
    const User = mongoose.models.TestUser || mongoose.model('TestUser', userSchema);
    Project = mongoose.models.Project || mongoose.model('Project'); // rely on existing
    Task = mongoose.models.Task || mongoose.model('Task');

    const user = await User.create({ email: 'sync@test.dev' });
    userId = user._id;
    token = makeToken(userId);
  }, 60000);

  test('creates a project via batch upsert (no id)', async () => {
    const res = await request(base)
      .post('/api/sync/batch')
      .set('Authorization', `Bearer ${token}`)
      .send({ operations: [{ entity: 'project', op: 'upsert', data: { name: 'Offline Project' }, clientId: 'c1' }] });

    expect(res.status).toBe(200);
    expect(Array.isArray(res.body.applied)).toBe(true);
    const created = res.body.applied.find(a => a.clientId === 'c1');
    expect(created).toBeTruthy();
    expect(created.version).toBe(0); // initial version
  });

  test('updates project with correct version increments', async () => {
    // Fetch created project
    const project = await Project.findOne({ name: 'Offline Project' });
    expect(project).toBeTruthy();

    const res = await request(base)
      .post('/api/sync/batch')
      .set('Authorization', `Bearer ${token}`)
      .send({ operations: [{ entity: 'project', op: 'upsert', id: String(project._id), version: project.version, data: { name: 'Offline Project v2' }, clientId: 'c2' }] });

    expect(res.status).toBe(200);
    const applied = res.body.applied.find(a => a.clientId === 'c2');
    expect(applied).toBeTruthy();
    expect(applied.version).toBe(project.version + 1);
  });

  test('conflict when using stale version', async () => {
    const project = await Project.findOne({ name: 'Offline Project v2' });
    expect(project).toBeTruthy();

    // Intentionally send an old version (project.version - 1)
    const staleVersion = project.version - 1;

    const res = await request(base)
      .post('/api/sync/batch')
      .set('Authorization', `Bearer ${token}`)
      .send({ operations: [{ entity: 'project', op: 'upsert', id: String(project._id), version: staleVersion, data: { name: 'Should Fail' }, clientId: 'c3' }] });

    expect(res.status).toBe(200);
    expect(res.body.conflicts.length).toBeGreaterThan(0);
    const conflict = res.body.conflicts.find(c => c.clientId === 'c3');
    expect(conflict).toBeTruthy();
    expect(conflict.reason).toBe('version-mismatch');
  });
});
