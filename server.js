require('dotenv').config();
const express = require('express');
const { createClient } = require('@libsql/client');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static('public'));

const JWT_SECRET = process.env.JWT_SECRET || 'secret123';
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;

let db;
let isDbInitialized = false;

async function getDb() {
  if (!db) {
    db = createClient({
      url: process.env.LAYERBASE_DATABASE_URL,
      authToken: process.env.LAYERBASE_AUTH_TOKEN,
    });
  }
  if (!isDbInitialized) {
    await db.execute(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, password TEXT, telegram_chat_id TEXT
    )`);
    try { await db.execute(`ALTER TABLE users ADD COLUMN telegram_chat_id TEXT`); } catch (e) {}
    
    await db.execute(`CREATE TABLE IF NOT EXISTS deadlines (
      id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, start_date TEXT, end_date TEXT, description TEXT
    )`);
    isDbInitialized = true;
  }
  return db;
}

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// --- АВТОРИЗАЦИЯ ---
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const database = await getDb();
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await database.execute({
      sql: `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`,
      args: [name, email, hashedPassword]
    });
    const userId = Number(result.lastInsertRowid); // Фикс BigInt
    const token = jwt.sign({ id: userId, email }, JWT_SECRET);
    res.json({ token, user: { id: userId, name, email } });
  } catch (error) {
    res.status(400).json({ error: "Email уже существует" });
  }
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const database = await getDb();
    const result = await database.execute({ sql: `SELECT * FROM users WHERE email = ?`, args: [email] });
    const user = result.rows[0];
    if (!user) return res.status(400).json({ error: "Неверный email или пароль" });
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: "Неверный email или пароль" });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  } catch (error) {
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// --- ДЕДЛАЙНЫ ---
app.get('/api/deadlines', authenticateToken, async (req, res) => {
  try {
    const database = await getDb();
    const result = await database.execute({ sql: `SELECT * FROM deadlines WHERE user_id = ? ORDER BY end_date ASC`, args: [req.user.id] });
    // Конвертируем id из BigInt в Number для каждой строки
    const rows = result.rows.map(row => ({ ...row, id: Number(row.id) }));
    res.json(rows);
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/deadlines', authenticateToken, async (req, res) => {
  const { title, start_date, end_date, description } = req.body;
  try {
    const database = await getDb();
    const result = await database.execute({
      sql: `INSERT INTO deadlines (user_id, title, start_date, end_date, description) VALUES (?, ?, ?, ?, ?)`,
      args: [req.user.id, title, start_date, end_date, description]
    });
    const newId = Number(result.lastInsertRowid); // Фикс BigInt
    res.json({ id: newId, title, start_date, end_date, description });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.delete('/api/deadlines/:id', authenticateToken, async (req, res) => {
  try {
    const database = await getDb();
    await database.execute({ sql: `DELETE FROM deadlines WHERE id = ? AND user_id = ?`, args: [req.params.id, req.user.id] });
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

// --- TELEGRAM ИНТЕГРАЦИЯ ---
app.get('/api/user/info', authenticateToken, async (req, res) => {
  try {
    const database = await getDb();
    const result = await database.execute({ sql: `SELECT telegram_chat_id FROM users WHERE id = ?`, args: [req.user.id] });
    res.json({ telegram_chat_id: result.rows[0]?.telegram_chat_id || null });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/link-telegram', authenticateToken, async (req, res) => {
  const { chat_id } = req.body;
  try {
    const database = await getDb();
    await database.execute({ sql: `UPDATE users SET telegram_chat_id = ? WHERE id = ?`, args: [chat_id, req.user.id] });
    res.json({ success: true });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

app.post('/api/telegram-webhook', async (req, res) => {
  try {
    const { message } = req.body;
    if (message && message.text === '/start') {
      const chatId = message.chat.id;
      if (BOT_TOKEN) {
        await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ chat_id: chatId, text: `Привет! Твой Chat ID: ${chatId}\n\nСкопируй его и вставь в настройках на сайте.` })
        });
      }
    }
    res.sendStatus(200);
  } catch (error) { res.sendStatus(500); }
});

app.get('/api/telegram-cron', async (req, res) => {
  try {
    const database = await getDb();
    const today = new Date().toISOString().split('T')[0];
    
    const result = await database.execute({
      sql: `SELECT d.title, d.description, d.end_date, u.telegram_chat_id 
            FROM deadlines d JOIN users u ON d.user_id = u.id 
            WHERE d.end_date = ? AND u.telegram_chat_id IS NOT NULL`,
      args: [today]
    });

    let sentCount = 0;
    for (const row of result.rows) {
      if (BOT_TOKEN) {
        await fetch(`https://api.telegram.org/bot${BOT_TOKEN}/sendMessage`, {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            chat_id: row.telegram_chat_id,
            text: `⚠️ Напоминание!\nСегодня последний день по дедлайну: *${row.title}*\n\n${row.description || ''}`,
            parse_mode: 'Markdown'
          })
        });
        sentCount++;
      }
    }
    res.json({ success: true, sent: sentCount });
  } catch (error) { res.status(500).json({ error: error.message }); }
});

module.exports = app;
if (process.env.NODE_ENV !== 'production') {
  app.listen(3000, () => console.log(`Сервер на http://localhost:3000`));
}