const express = require('express');
const path = require('path');
const { Pool } = require('pg');

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '2mb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

app.get('/health', async (_req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, database: 'connected' });
  } catch (error) {
    console.error('Health check failed:', error.message);
    res.status(503).json({ ok: false, database: 'unavailable' });
  }
});

app.get('/api/salary-table', async (_req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT table_data, updated_at FROM salary_table WHERE table_key = 'main' LIMIT 1"
    );
    res.json(rows[0] || { table_data: null, updated_at: null });
  } catch (error) {
    console.error('Read salary table failed:', error.message);
    res.status(500).json({ error: 'ไม่สามารถอ่านตารางเงินเดือนได้' });
  }
});

app.put('/api/salary-table', async (req, res) => {
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

app.use(express.static(path.join(__dirname, 'public')));
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
