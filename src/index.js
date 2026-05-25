import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { SignJWT, jwtVerify } from 'jose';

// ─── Password helpers (Web Crypto PBKDF2 — no library, ~3-8ms, fits free tier) ─
const PBKDF2_ITERATIONS = 100_000;

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    key, 256
  );
  const toHex = (buf) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
  return `pbkdf2:${toHex(salt.buffer)}:${toHex(bits)}`;
}

async function verifyPassword(password, stored) {
  // Legacy bcrypt hash from MySQL migration — cannot verify on free tier.
  // Return null to trigger the password-reset flow.
  if (stored.startsWith('$2')) return null;

  const [, saltHex, hashHex] = stored.split(':');
  const salt = Uint8Array.from(saltHex.match(/.{2}/g).map(h => parseInt(h, 16)));
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    key, 256
  );
  const computed = [...new Uint8Array(bits)].map(b => b.toString(16).padStart(2, '0')).join('');
  return computed === hashHex;
}

const app = new Hono();

// ─── CORS ─────────────────────────────────────────────────────────────────────
app.use('*', cors({
  origin: (origin, c) => {
    const allowed = [
      ...(c.env.CORS_ALLOWED_ORIGINS || '').split(',').map(o => o.trim()).filter(Boolean),
      'http://localhost:3000',
      'http://127.0.0.1:3000',
    ];
    return allowed.includes(origin) ? origin : null;
  },
  credentials: true,
  allowMethods: ['GET', 'HEAD', 'PUT', 'PATCH', 'POST', 'DELETE'],
}));

// ─── Global error handler ──────────────────────────────────────────────────────
app.onError((err, c) => {
  console.error(err);
  return c.json({ error: err.message || 'Internal server error' }, 500);
});

// ─── Auth middleware ───────────────────────────────────────────────────────────
const auth = async (c, next) => {
  const header = c.req.header('Authorization');
  if (!header?.startsWith('Bearer ')) return c.json({ error: 'No token provided' }, 401);
  try {
    const secret = new TextEncoder().encode(c.env.JWT_SECRET || 'your-secret-key');
    const { payload } = await jwtVerify(header.slice(7), secret);
    c.set('user', payload);
    await next();
  } catch {
    return c.json({ error: 'Invalid token' }, 401);
  }
};

// ─── Broadcast helper ──────────────────────────────────────────────────────────
// Notifies all connected WebSocket clients that data has changed.
async function broadcast(env) {
  try {
    const stub = env.BROADCAST.get(env.BROADCAST.idFromName('global'));
    await stub.fetch('https://do/notify');
  } catch {}
}

// ─── Date normalization ────────────────────────────────────────────────────────
// D1 stores datetime as "YYYY-MM-DD HH:MM:SS"; strip the time portion.
function normalizeDates(logs) {
  return logs.map(log => ({
    ...log,
    created_at: log.created_at
      ? log.created_at.split('T')[0].split(' ')[0]
      : log.created_at,
  }));
}

// ─── Users ────────────────────────────────────────────────────────────────────
app.get('/api/users', async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT * FROM users ORDER BY created_at DESC'
  ).all();
  return c.json(results);
});

app.post('/api/users', async (c) => {
  const { id, email, password, fullName, role } = await c.req.json();
  const hashed = await hashPassword(password);
  await c.env.DB.prepare(
    'INSERT INTO users (id, email, password, fullName, role, status) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(id, email, hashed, fullName, role, 'active').run();
  await broadcast(c.env);
  return c.json({ success: true });
});

app.put('/api/users/:id/status', async (c) => {
  const { status } = await c.req.json();
  await c.env.DB.prepare('UPDATE users SET status = ? WHERE id = ?')
    .bind(status, c.req.param('id')).run();
  await broadcast(c.env);
  return c.json({ success: true });
});

app.put('/api/users/:id/password', async (c) => {
  const { password } = await c.req.json();
  if (!password) return c.json({ error: 'Password cannot be empty' }, 400);
  const hashed = await hashPassword(password);
  await c.env.DB.batch([
    c.env.DB.prepare('UPDATE users SET must_change_password = 0 WHERE id = ?').bind(c.req.param('id')),
    c.env.DB.prepare('UPDATE users SET password = ? WHERE id = ?').bind(hashed, c.req.param('id')),
  ]);
  await broadcast(c.env);
  return c.json({ success: true, message: 'Password reset successfully' });
});

app.put('/api/users/:id/leave-credits', async (c) => {
  const { credits } = await c.req.json();
  await c.env.DB.prepare('UPDATE users SET leaveCredits = ? WHERE id = ?')
    .bind(credits, c.req.param('id')).run();
  await broadcast(c.env);
  return c.json({ success: true });
});

// ─── Pending Users ─────────────────────────────────────────────────────────────
app.get('/api/pending-users', async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT * FROM pending_users ORDER BY created_at DESC'
  ).all();
  return c.json(results);
});

app.post('/api/pending-users', async (c) => {
  const { id, email, password, fullName, role } = await c.req.json();
  const [inUsers, inPending] = await Promise.all([
    c.env.DB.prepare('SELECT email FROM users WHERE email = ?').bind(email).first(),
    c.env.DB.prepare('SELECT email FROM pending_users WHERE email = ?').bind(email).first(),
  ]);
  if (inUsers || inPending) return c.json({ error: 'Email already registered' }, 409);
  const hashed = await hashPassword(password);
  await c.env.DB.prepare(
    'INSERT INTO pending_users (id, email, password, fullName, role) VALUES (?, ?, ?, ?, ?)'
  ).bind(id, email, hashed, fullName, role).run();
  await broadcast(c.env);
  return c.json({ success: true });
});

app.post('/api/approve-user', async (c) => {
  const { userId } = await c.req.json();
  const user = await c.env.DB.prepare(
    'SELECT * FROM pending_users WHERE id = ?'
  ).bind(userId).first();
  if (!user) return c.json({ error: 'User not found' }, 404);

  const existing = await c.env.DB.prepare(
    'SELECT id FROM users WHERE email = ?'
  ).bind(user.email).first();
  if (existing) return c.json({ error: 'Email already registered' }, 409);

  await c.env.DB.batch([
    c.env.DB.prepare(
      'INSERT INTO users (id, email, password, fullName, role, status, leaveCredits, must_change_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(user.id, user.email, user.password, user.fullName, user.role, 'active', 20, 0),
    c.env.DB.prepare('DELETE FROM pending_users WHERE id = ?').bind(userId),
  ]);
  await broadcast(c.env);
  return c.json({ success: true });
});

app.delete('/api/pending-users/:id', async (c) => {
  await c.env.DB.prepare('DELETE FROM pending_users WHERE id = ?')
    .bind(c.req.param('id')).run();
  await broadcast(c.env);
  return c.json({ success: true });
});

// ─── Logs ──────────────────────────────────────────────────────────────────────
app.get('/api/logs', async (c) => {
  const { page: rawPage, limit: rawLimit, date, userEmail } = c.req.query();
  let page = rawPage ? parseInt(rawPage, 10) : null;
  let limit = rawLimit ? parseInt(rawLimit, 10) : null;

  const whereClauses = [];
  const params = [];

  if (date) {
    const parsed = new Date(date);
    if (!isNaN(parsed.getTime())) {
      whereClauses.push("DATE(created_at) = ?");
      params.push(parsed.toISOString().split('T')[0]);
    }
  }
  if (userEmail) {
    whereClauses.push('userEmail = ?');
    params.push(userEmail);
  }

  const where = whereClauses.length > 0 ? ` WHERE ${whereClauses.join(' AND ')}` : '';

  if (page != null || limit != null) {
    page = Math.max(page || 1, 1);
    limit = Math.max(limit || 50, 1);
    const offset = (page - 1) * limit;

    const countRow = await c.env.DB.prepare(
      `SELECT COUNT(*) AS totalCount FROM logs${where}`
    ).bind(...params).first();
    const totalCount = countRow?.totalCount || 0;
    const totalPages = Math.max(Math.ceil(totalCount / limit), 1);

    const { results: logs } = await c.env.DB.prepare(
      `SELECT * FROM logs${where} ORDER BY created_at DESC LIMIT ? OFFSET ?`
    ).bind(...params, limit, offset).all();

    return c.json({
      logs: normalizeDates(logs),
      currentPage: page,
      totalPages,
      totalCount,
      pageSize: limit,
    });
  }

  const { results: logs } = await c.env.DB.prepare(
    `SELECT * FROM logs${where} ORDER BY created_at DESC LIMIT 50`
  ).bind(...params).all();
  return c.json(normalizeDates(logs));
});

app.post('/api/logs', async (c) => {
  const { userEmail, userName, type, timestamp, image, location, created_at, todo, progress } =
    await c.req.json();
  await c.env.DB.prepare(
    `INSERT INTO logs (userEmail, userName, type, timestamp, image, location, todo, progress, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, datetime('now')))`
  ).bind(
    userEmail, userName, type, timestamp,
    image ?? null, location ?? null,
    todo ?? null, progress ?? null,
    created_at ?? null
  ).run();
  await broadcast(c.env);
  return c.json({ success: true });
});

app.patch('/api/logs/:id', async (c) => {
  const { todo, progress } = await c.req.json();
  const fields = [];
  const values = [];
  if (todo !== undefined) { fields.push('todo = ?'); values.push(todo); }
  if (progress !== undefined) { fields.push('progress = ?'); values.push(progress); }
  if (fields.length === 0) return c.json({ error: 'No fields to update provided.' }, 400);
  values.push(c.req.param('id'));
  await c.env.DB.prepare(`UPDATE logs SET ${fields.join(', ')} WHERE id = ?`)
    .bind(...values).run();
  await broadcast(c.env);
  return c.json({ success: true, message: 'Log updated successfully.' });
});

app.delete('/api/logs/:id', async (c) => {
  await c.env.DB.prepare('DELETE FROM logs WHERE id = ?')
    .bind(c.req.param('id')).run();
  await broadcast(c.env);
  return c.json({ success: true });
});

// ─── Holiday Requests ──────────────────────────────────────────────────────────
app.get('/api/holiday-requests', async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT * FROM holiday_requests ORDER BY timestamp DESC'
  ).all();
  return c.json(results);
});

app.post('/api/holiday-requests', async (c) => {
  const { id, userEmail, userName, holidayName, holidayDate, details, status, timestamp } =
    await c.req.json();
  await c.env.DB.prepare(
    'INSERT INTO holiday_requests (id, userEmail, userName, holidayName, holidayDate, details, status, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
  ).bind(id, userEmail, userName, holidayName, holidayDate, details ?? null, status, timestamp).run();
  await broadcast(c.env);
  return c.json({ success: true });
});

app.put('/api/holiday-requests/:id', async (c) => {
  const { status } = await c.req.json();
  await c.env.DB.prepare('UPDATE holiday_requests SET status = ? WHERE id = ?')
    .bind(status, c.req.param('id')).run();
  await broadcast(c.env);
  return c.json({ success: true });
});

app.delete('/api/holiday-requests/:id', async (c) => {
  await c.env.DB.prepare('DELETE FROM holiday_requests WHERE id = ?')
    .bind(c.req.param('id')).run();
  await broadcast(c.env);
  return c.json({ success: true });
});

// ─── Leave Applications ────────────────────────────────────────────────────────
app.get('/api/leave-applications', async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT * FROM leave_applications ORDER BY timestamp DESC'
  ).all();
  return c.json(results);
});

app.post('/api/leave-applications', async (c) => {
  const body = await c.req.json();
  const { id, userEmail, userName, leaveType, startDate, details, status, timestamp, dayType, payType, halfDayShift } = body;
  const endDate = body.endDate || startDate;
  await c.env.DB.prepare(
    `INSERT INTO leave_applications
     (id, userEmail, userName, leaveType, startDate, endDate, details, status, timestamp, dayType, payType, halfDayShift)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    id, userEmail, userName, leaveType, startDate, endDate,
    details ?? null, status, timestamp, dayType, payType,
    dayType === 'half' ? halfDayShift : null
  ).run();
  await broadcast(c.env);
  return c.json({ success: true });
});

app.put('/api/leave-applications/:id', async (c) => {
  const { status } = await c.req.json();
  const id = c.req.param('id');

  const application = await c.env.DB.prepare(
    'SELECT * FROM leave_applications WHERE id = ?'
  ).bind(id).first();
  if (!application) return c.json({ error: 'Leave application not found' }, 404);

  const prevStatus = application.status;

  if (prevStatus !== status) {
    const duration = application.dayType === 'half'
      ? 0.5
      : (new Date(application.endDate) - new Date(application.startDate)) / 86400000 + 1;

    const stmts = [
      c.env.DB.prepare('UPDATE leave_applications SET status = ? WHERE id = ?').bind(status, id),
    ];

    if (status === 'approved' && application.payType === 'withPay') {
      stmts.push(
        c.env.DB.prepare('UPDATE users SET leaveCredits = leaveCredits - ? WHERE email = ?')
          .bind(duration, application.userEmail)
      );
    } else if (prevStatus === 'approved') {
      stmts.push(
        c.env.DB.prepare('UPDATE users SET leaveCredits = leaveCredits + ? WHERE email = ?')
          .bind(duration, application.userEmail)
      );
    }

    await c.env.DB.batch(stmts);
  } else {
    await c.env.DB.prepare('UPDATE leave_applications SET status = ? WHERE id = ?')
      .bind(status, id).run();
  }

  await broadcast(c.env);
  return c.json({ success: true });
});

app.delete('/api/leave-applications/:id', async (c) => {
  const id = c.req.param('id');
  const application = await c.env.DB.prepare(
    'SELECT * FROM leave_applications WHERE id = ?'
  ).bind(id).first();
  if (!application) return c.json({ success: true, message: 'Application not found, but considering it deleted.' });

  const stmts = [
    c.env.DB.prepare('DELETE FROM leave_applications WHERE id = ?').bind(id),
  ];

  if (application.status === 'approved') {
    const duration = application.dayType === 'half'
      ? 0.5
      : (new Date(application.endDate) - new Date(application.startDate)) / 86400000 + 1;
    stmts.push(
      c.env.DB.prepare('UPDATE users SET leaveCredits = leaveCredits + ? WHERE email = ?')
        .bind(duration, application.userEmail)
    );
  }

  await c.env.DB.batch(stmts);
  await broadcast(c.env);
  return c.json({ success: true });
});

// ─── Password Reset Requests ───────────────────────────────────────────────────
app.get('/api/password-reset-requests', async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT * FROM password_reset_requests ORDER BY timestamp DESC'
  ).all();
  return c.json(results);
});

app.post('/api/password-reset-requests', async (c) => {
  const { email } = await c.req.json();
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();
  if (!user) return c.json({ error: 'No user found with this email address.' }, 404);

  const pending = await c.env.DB.prepare(
    'SELECT * FROM password_reset_requests WHERE userEmail = ? AND status = "pending"'
  ).bind(email).first();
  if (pending) return c.json({ error: 'A password reset request for this account is already pending.' }, 409);

  await c.env.DB.prepare(
    'INSERT INTO password_reset_requests (id, userEmail, userName, timestamp) VALUES (?, ?, ?, ?)'
  ).bind(crypto.randomUUID(), user.email, user.fullName, new Date().toISOString()).run();

  await broadcast(c.env);
  return c.json({ success: true, message: 'Password reset request submitted successfully.' });
});

app.put('/api/password-reset-requests/:id', async (c) => {
  const { status } = await c.req.json();
  const id = c.req.param('id');

  const request = await c.env.DB.prepare(
    'SELECT * FROM password_reset_requests WHERE id = ?'
  ).bind(id).first();
  if (!request) return c.json({ error: 'Request not found.' }, 404);

  let tempPassword = null;
  const stmts = [];

  if (status === 'approved') {
    tempPassword = Math.random().toString(36).slice(-8);
    const hashed = await hashPassword(tempPassword);
    stmts.push(
      c.env.DB.prepare('UPDATE users SET password = ?, must_change_password = 1 WHERE email = ?')
        .bind(hashed, request.userEmail)
    );
  }

  stmts.push(
    c.env.DB.prepare('UPDATE password_reset_requests SET status = ?, tempPassword = ? WHERE id = ?')
      .bind(status, tempPassword, id)
  );

  await c.env.DB.batch(stmts);
  await broadcast(c.env);
  return c.json({ success: true, tempPassword });
});

// ─── Auth ──────────────────────────────────────────────────────────────────────
app.post('/api/auth/login', async (c) => {
  const { email, password } = await c.req.json();
  const user = await c.env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();

  if (user) {
    if (user.status === 'disabled') return c.json({ error: 'Your account has been disabled.' }, 403);
    const match = await verifyPassword(password, user.password);
    // match === null means legacy bcrypt hash (migrated from MySQL) — requires password reset
    if (match === null) return c.json({ error: 'Your account was migrated. Please reset your password using the Forgot Password option.' }, 403);
    if (!match) return c.json({ error: 'Invalid credentials' }, 401);

    const secret = new TextEncoder().encode(c.env.JWT_SECRET || 'your-secret-key');
    const token = await new SignJWT({ email: user.email, role: user.role })
      .setProtectedHeader({ alg: 'HS256' })
      .setExpirationTime('24h')
      .sign(secret);

    return c.json({
      success: true,
      user: { ...user, must_change_password: Boolean(user.must_change_password) },
      token,
    });
  }

  const pending = await c.env.DB.prepare('SELECT * FROM pending_users WHERE email = ?').bind(email).first();
  if (pending) return c.json({ error: 'Account pending approval' }, 403);
  return c.json({ error: 'Invalid credentials' }, 401);
});

// ─── R2 Image Upload ───────────────────────────────────────────────────────────
app.post('/api/upload', async (c) => {
  const formData = await c.req.formData();
  const file = formData.get('image');
  if (!file || !(file instanceof File)) return c.json({ error: 'No image provided' }, 400);

  const ext = file.name.split('.').pop() || 'jpg';
  const key = `logs/${crypto.randomUUID()}.${ext}`;
  await c.env.BUCKET.put(key, file.stream(), {
    httpMetadata: { contentType: file.type },
  });

  // If R2_PUBLIC_URL is set (e.g. a public bucket domain), return a direct link.
  // Otherwise, images are served via the /api/images/* route below.
  const base = c.env.R2_PUBLIC_URL || `https://${c.req.header('host')}/api/images`;
  return c.json({ success: true, url: `${base}/${key}` });
});

// Serve R2 images through the Worker (only needed if the bucket is not public)
app.get('/api/images/*', async (c) => {
  const key = c.req.path.replace('/api/images/', '');
  const object = await c.env.BUCKET.get(key);
  if (!object) return c.json({ error: 'Not found' }, 404);
  return new Response(object.body, {
    headers: { 'Content-Type': object.httpMetadata?.contentType || 'application/octet-stream' },
  });
});

// ─── WebSocket ─────────────────────────────────────────────────────────────────
// Upgrade is handled by the BroadcastDO Durable Object below.
app.get('/ws', async (c) => {
  if (c.req.header('Upgrade') !== 'websocket') {
    return c.json({ error: 'Expected WebSocket upgrade' }, 426);
  }
  const stub = c.env.BROADCAST.get(c.env.BROADCAST.idFromName('global'));
  return stub.fetch(c.req.raw);
});

export default app;

// ─── Durable Object: WebSocket broadcast ──────────────────────────────────────
// Holds all live WebSocket connections and fans out data-change events.
export class BroadcastDO {
  constructor(state) {
    this.state = state;
    this.connections = new Set();
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (request.headers.get('Upgrade') === 'websocket') {
      const pair = new WebSocketPair();
      const [client, server] = Object.values(pair);
      server.accept();
      this.connections.add(server);
      server.addEventListener('close', () => this.connections.delete(server));
      server.addEventListener('error', () => this.connections.delete(server));
      return new Response(null, { status: 101, webSocket: client });
    }

    if (url.pathname === '/notify') {
      const msg = JSON.stringify({ type: 'data-changed' });
      for (const ws of [...this.connections]) {
        try { ws.send(msg); } catch { this.connections.delete(ws); }
      }
      return new Response('OK');
    }

    return new Response('Not Found', { status: 404 });
  }
}
