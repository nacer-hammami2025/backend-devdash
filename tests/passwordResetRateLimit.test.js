const request = require('supertest');
const express = require('express');
require('dotenv').config({ path: __dirname + '/../.env' });

// Force test env & enable limiter behavior
process.env.NODE_ENV = 'test';
process.env.ENABLE_RESET_RATE_LIMIT = 'true';
process.env.PASSWORD_RESET_WINDOW_MS = '2000'; // 2s short window for test
process.env.PASSWORD_RESET_MAX_PER_EMAIL = '3';
process.env.PASSWORD_RESET_MAX_PER_IP = '5';

// Build minimal app using the auth router
const authRouter = require('../routes/auth');
const app = express();
app.use(express.json());
app.use('/api/auth', authRouter);

// Mock User model to avoid DB calls (only need existence check)
jest.mock('../models/User', () => ({
  findOne: jest.fn(async (q) => {
    if (q.email === 'existing@example.com') return { _id: 'user123', email: 'existing@example.com' };
    return null;
  }),
}));

// Mock AuditLog (noop)
jest.mock('../models/AuditLog', () => ({
  create: jest.fn(async () => { })
}));

// Mock mailer to avoid real send
jest.mock('../utils/mailer', () => ({
  sendEmail: jest.fn(async () => { })
}));

// Provide minimal bcrypt to satisfy reset route (not used here but imported)

// Test suite
describe('Password reset rate limiting', () => {
  test('limits by email after threshold', async () => {
    const agent = request(app);
    for (let i = 0; i < 3; i++) {
      const res = await agent.post('/api/auth/password/forgot').send({ email: 'existing@example.com' });
      expect(res.status).toBe(200);
    }
    const blocked = await agent.post('/api/auth/password/forgot').send({ email: 'existing@example.com' });
    expect(blocked.status).toBe(429);
    expect(blocked.body.message).toMatch(/Too many reset requests/);
  });

  test('separate email counters do not interfere', async () => {
    const agent = request(app);
    const r1 = await agent.post('/api/auth/password/forgot').send({ email: 'a@example.com' });
    const r2 = await agent.post('/api/auth/password/forgot').send({ email: 'b@example.com' });
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
  });

  test('IP limit triggers after threshold without email variance', async () => {
    const agent = request(app);
    // 5 allowed (mix emails) then block
    const emails = ['e1@example.com', 'e2@example.com', 'e3@example.com', 'e4@example.com', 'e5@example.com'];
    for (let i = 0; i < emails.length; i++) {
      const res = await agent.post('/api/auth/password/forgot').send({ email: emails[i] });
      expect(res.status).toBe(200);
    }
    const blocked = await agent.post('/api/auth/password/forgot').send({ email: 'e6@example.com' });
    expect(blocked.status).toBe(429);
  });

  test('window expiry resets counters', async () => {
    const agent = request(app);
    for (let i = 0; i < 3; i++) {
      await agent.post('/api/auth/password/forgot').send({ email: 'win@example.com' });
    }
    const blocked = await agent.post('/api/auth/password/forgot').send({ email: 'win@example.com' });
    expect(blocked.status).toBe(429);
    // wait for 2.2s to surpass window
    await new Promise(r => setTimeout(r, 2200));
    const after = await agent.post('/api/auth/password/forgot').send({ email: 'win@example.com' });
    expect(after.status).toBe(200);
  });
});
