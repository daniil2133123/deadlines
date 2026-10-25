require('dotenv').config();
const express = require('express');
const { createClient } = require('@libsql/client/web'); // Важно: /web
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static('public'));

const JWT_SECRET = process.env.JWT_SECRET || 'secret123';

let db;
let isDbInitialized = false;

// Ленивое подключение к базе (защита от таймаутов)
async function getDb() {
  if (!db) {
    db = createClient({
      url: process.env.LAYERBASE_DATABASE_URL,
      authToken: process.env.LAYERBASE_AUTH_TOKEN,
    });
  }
  if (!isDbInitialized) {
    await db.execute(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, password TEXT
    )`);
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

// --- Регистрация ---
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const database = await getDb();
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await database.execute({
      sql: `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`,
      args: [name, email, hashedPassword]
    });
    const token = jwt.sign({ id: result.lastInsertRowid, email }, JWT_SECRET);
    res.json({ token, user: { id: result.lastInsertRowid, name, email } });
    } catch (error) {
    console.error("ОШИБКА БАЗЫ:", error); // Это покажет ошибку в логах Netlify
    res.status(400).json({ error: error.message || "Ошибка при регистрации" });
  }
});

// --- Вход ---
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const database = await getDb();
    const result = await database.execute({
      sql: `SELECT * FROM users WHERE email = ?`,
      args: [email]
    });
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

// --- Дедлайны ---
app.get('/api/deadlines', authenticateToken, async (req, res) => {
  try {
    const database = await getDb();
    const result = await database.execute({
      sql: `SELECT * FROM deadlines WHERE user_id = ? ORDER BY end_date ASC`,
      args: [req.user.id]
    });
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/deadlines', authenticateToken, async (req, res) => {
  const { title, start_date, end_date, description } = req.body;
  try {
    const database = await getDb();
    const result = await database.execute({
      sql: `INSERT INTO deadlines (user_id, title, start_date, end_date, description) VALUES (?, ?, ?, ?, ?)`,
      args: [req.user.id, title, start_date, end_date, description]
    });
    res.json({ id: result.lastInsertRowid, title, start_date, end_date, description });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/deadlines/:id', authenticateToken, async (req, res) => {
  try {
    const database = await getDb();
    await database.execute({
      sql: `DELETE FROM deadlines WHERE id = ? AND user_id = ?`,
      args: [req.params.id, req.user.id]
    });
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
// Добавьте этот маршрут где-нибудь до экспорта
app.get('/api/ping', (req, res) => {
  res.json({ ok: true, message: 'Функция работает!' });
});
// Экспорт для Netlify
module.exports = app;

// Локальный запуск (не используется на Netlify)
if (process.env.NODE_ENV !== 'production') {
  app.listen(3000, () => console.log(`Сервер на http://localhost:3000`));
}