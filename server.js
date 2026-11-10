const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { rateLimit } = require('express-rate-limit');

const app = express();
const isProduction = process.env.NODE_ENV === 'production';
app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(express.json({ limit: '2mb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

app.use(session({
  store: new PgSession({
    pool,
    tableName: 'user_sessions',
    createTableIfMissing: true,
    pruneSessionInterval: 60 * 15,
  }),
  name: 'police_salary_session',
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  proxy: isProduction,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: 'lax',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  },
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'ลองเข้าสู่ระบบใหม่อีกครั้งในอีก 15 นาที' },
});

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'กรุณาเข้าสู่ระบบก่อนใช้งาน' });
  }
  next();
}

function publicUser(row) {
  return { id: row.id, email: row.email, display_name: row.display_name };
}

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, database: 'connected' });
  } catch (error) {
    console.error('Health check failed:', error.message);
    res.status(503).json({ ok: false, database: 'unavailable' });
  }
});

app.post('/api/auth/register', authLimiter, async (req, res) => {
  const displayName = String(req.body?.display_name || '').trim();
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');

  if (displayName.length < 2 || displayName.length > 80) {
    return res.status(400).json({ error: 'กรุณากรอกชื่อ 2-80 ตัวอักษร' });
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || email.length > 254) {
    return res.status(400).json({ error: 'รูปแบบอีเมลไม่ถูกต้อง' });
  }
  if (password.length < 10 || password.length > 128) {
    return res.status(400).json({ error: 'รหัสผ่านต้องมีอย่างน้อย 10 ตัวอักษร' });
  }

  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      'INSERT INTO app_users (email, display_name, password_hash) VALUES ($1, $2, $3) RETURNING id, email, display_name',
      [email, displayName, passwordHash]
    );
    await new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
    req.session.userId = rows[0].id;
    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));
    res.status(201).json({ user: publicUser(rows[0]) });
  } catch (error) {
    if (error.code === '23505') return res.status(409).json({ error: 'อีเมลนี้มีบัญชีอยู่แล้ว' });
    console.error('Register failed:', error.message);
    res.status(500).json({ error: 'ไม่สามารถสร้างบัญชีได้ในขณะนี้' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const email = String(req.body?.email || '').trim().toLowerCase();
  const password = String(req.body?.password || '');
  try {
    const { rows } = await pool.query(
      'SELECT id, email, display_name, password_hash FROM app_users WHERE email = $1 LIMIT 1',
      [email]
    );
    const user = rows[0];
    const valid = user ? await bcrypt.compare(password, user.password_hash) : false;
    if (!valid) return res.status(401).json({ error: 'อีเมลหรือรหัสผ่านไม่ถูกต้อง' });

    await new Promise((resolve, reject) => req.session.regenerate(err => err ? reject(err) : resolve()));
    req.session.userId = user.id;
    await pool.query('UPDATE app_users SET last_login_at = NOW() WHERE id = $1', [user.id]);
    await new Promise((resolve, reject) => req.session.save(err => err ? reject(err) : resolve()));
    res.json({ user: publicUser(user) });
  } catch (error) {
    console.error('Login failed:', error.message);
    res.status(500).json({ error: 'ไม่สามารถเข้าสู่ระบบได้ในขณะนี้' });
  }
});

app.get('/api/auth/me', async (req, res) => {
  if (!req.session?.userId) return res.status(401).json({ error: 'ยังไม่ได้เข้าสู่ระบบ' });
  try {
    const { rows } = await pool.query(
      'SELECT id, email, display_name FROM app_users WHERE id = $1 LIMIT 1',
      [req.session.userId]
    );
    if (!rows[0]) return req.session.destroy(() => res.status(401).json({ error: 'ไม่พบบัญชีผู้ใช้' }));
    res.set('Cache-Control', 'no-store');
    res.json({ user: publicUser(rows[0]) });
  } catch (error) {
    console.error('Session lookup failed:', error.message);
    res.status(500).json({ error: 'ไม่สามารถตรวจสอบบัญชีได้' });
  }
});

app.post('/api/auth/logout', requireAuth, (req, res) => {
  req.session.destroy(error => {
    if (error) return res.status(500).json({ error: 'ออกจากระบบไม่สำเร็จ' });
    res.clearCookie('police_salary_session', {
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
    });
    res.json({ ok: true });
  });
});

app.get('/api/salary-table', requireAuth, async (_req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT table_data, updated_at FROM salary_table WHERE table_key = 'main' LIMIT 1"
    );
    res.set('Cache-Control', 'no-store');
    res.json(rows[0] || { table_data: null, updated_at: null });
  } catch (error) {
    console.error('Read salary table failed:', error.message);
    res.status(500).json({ error: 'ไม่สามารถอ่านตารางเงินเดือนได้' });
  }
});

app.put('/api/salary-table', requireAuth, async (req, res) => {
  const expectedKey = process.env.ADMIN_WRITE_KEY;
  const providedKey = (req.get('authorization') || '').replace(/^Bearer\s+/i, '');
  if (!expectedKey || providedKey !== expectedKey) {
    return res.status(401).json({ error: 'ไม่มีสิทธิ์แก้ไขตารางเงินเดือนส่วนกลาง' });
  }
  const tableData = req.body && req.body.table_data;
  if (!tableData || typeof tableData !== 'object' || Array.isArray(tableData)) {
    return res.status(400).json({ error: 'รูปแบบตารางเงินเดือนไม่ถูกต้อง' });
  }
  try {
    const { rows } = await pool.query(
      `INSERT INTO salary_table (table_key, table_data, updated_at)
       VALUES ('main', $1::jsonb, NOW())
       ON CONFLICT (table_key)
       DO UPDATE SET table_data = EXCLUDED.table_data, updated_at = NOW()
       RETURNING updated_at`,
      [JSON.stringify(tableData)]
    );
    res.json({ ok: true, updated_at: rows[0].updated_at });
  } catch (error) {
    console.error('Save salary table failed:', error.message);
    res.status(500).json({ error: 'ไม่สามารถบันทึกตารางเงินเดือนได้' });
  }
});

app.get('/api/calculations', requireAuth, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, title, input_data, result_data, created_at FROM calculation_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT 100',
      [req.session.userId]
    );
    res.set('Cache-Control', 'no-store');
    res.json({ items: rows });
  } catch (error) {
    console.error('Read calculation history failed:', error.message);
    res.status(500).json({ error: 'ไม่สามารถอ่านประวัติการคำนวณได้' });
  }
});

app.post('/api/calculations', requireAuth, async (req, res) => {
  const title = String(req.body?.title || 'รายการคำนวณ').trim().slice(0, 100) || 'รายการคำนวณ';
  const inputData = req.body?.input_data;
  const resultData = req.body?.result_data;
  if (!inputData || typeof inputData !== 'object' || Array.isArray(inputData) ||
      !resultData || typeof resultData !== 'object' || Array.isArray(resultData)) {
    return res.status(400).json({ error: 'ข้อมูลการคำนวณไม่ถูกต้อง' });
  }
  try {
    const { rows } = await pool.query(
      'INSERT INTO calculation_history (user_id, title, input_data, result_data) VALUES ($1, $2, $3::jsonb, $4::jsonb) RETURNING id, title, created_at',
      [req.session.userId, title, JSON.stringify(inputData), JSON.stringify(resultData)]
    );
    res.status(201).json({ item: rows[0] });
  } catch (error) {
    console.error('Save calculation failed:', error.message);
    res.status(500).json({ error: 'บันทึกประวัติไม่สำเร็จ' });
  }
});

app.delete('/api/calculations/:id', requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isSafeInteger(id) || id < 1) return res.status(400).json({ error: 'รหัสรายการไม่ถูกต้อง' });
  try {
    const result = await pool.query(
      'DELETE FROM calculation_history WHERE id = $1 AND user_id = $2',
      [id, req.session.userId]
    );
    if (!result.rowCount) return res.status(404).json({ error: 'ไม่พบรายการนี้' });
    res.json({ ok: true });
  } catch (error) {
    console.error('Delete calculation failed:', error.message);
    res.status(500).json({ error: 'ลบประวัติไม่สำเร็จ' });
  }
});

// Always serve the latest login screen instead of a cached pre-authentication page.
app.use((req, res, next) => {
  if (req.path === '/' || req.path.endsWith('.html')) {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
  }
  next();
});
app.use(express.static(path.join(__dirname, 'public'), { etag: false, lastModified: false }));
app.get('*', (_req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const port = Number(process.env.PORT || 3000);
const server = app.listen(port, '0.0.0.0', () => console.log(`Server listening on ${port}`));

async function shutdown() {
  server.close(async () => {
    await pool.end();
    process.exit(0);
  });
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
