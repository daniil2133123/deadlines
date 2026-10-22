require('dotenv').config();
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const cron = require('node-cron');
const TelegramBot = require('node-telegram-bot-api');
const { SocksProxyAgent } = require('socks-proxy-agent');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static('public')); // Отдаем файлы фронтенда

const JWT_SECRET = process.env.JWT_SECRET || 'secret123';
const PORT = process.env.PORT || 3000;

// --- Инициализация Базы Данных ---
const db = new sqlite3.Database('./database.db');
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    email TEXT UNIQUE,
    password TEXT,
    telegram_chat_id TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS deadlines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    title TEXT,
    start_date TEXT,
    end_date TEXT,
    description TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

// --- Middleware для проверки JWT ---
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

// --- Роуты Авторизации ---
app.post('/api/register', async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(`INSERT INTO users (name, email, password) VALUES (?, ?, ?)`, 
      [name, email, hashedPassword], 
      function(err) {
        if (err) return res.status(400).json({ error: "Email уже существует" });
        const token = jwt.sign({ id: this.lastID, email }, JWT_SECRET);
        res.json({ token, user: { id: this.lastID, name, email } });
      }
    );
  } catch (error) {
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body;
  db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
    if (err || !user) return res.status(400).json({ error: "Неверный email или пароль" });
    
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) return res.status(400).json({ error: "Неверный email или пароль" });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET);
    res.json({ token, user: { id: user.id, name: user.name, email: user.email } });
  });
});

// --- Привязка Telegram ---
app.post('/api/link-telegram', authenticateToken, (req, res) => {
  const { chat_id } = req.body;
  db.run(`UPDATE users SET telegram_chat_id = ? WHERE id = ?`, [chat_id, req.user.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// --- Роуты Дедлайнов ---
app.get('/api/deadlines', authenticateToken, (req, res) => {
  db.all(`SELECT * FROM deadlines WHERE user_id = ? ORDER BY end_date ASC`, [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post('/api/deadlines', authenticateToken, (req, res) => {
  const { title, start_date, end_date, description } = req.body;
  db.run(`INSERT INTO deadlines (user_id, title, start_date, end_date, description) VALUES (?, ?, ?, ?, ?)`,
    [req.user.id, title, start_date, end_date, description],
    function(err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, title, start_date, end_date, description });
    }
  );
});

app.delete('/api/deadlines/:id', authenticateToken, (req, res) => {
  db.run(`DELETE FROM deadlines WHERE id = ? AND user_id = ?`, [req.params.id, req.user.id], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ success: true });
  });
});

// ... (код с app.get, app.post и app.delete для дедлайнов) ...

// 👇 ВОТ НОВЫЙ БЛОК С БОТОМ 👇
if (process.env.TELEGRAM_BOT_TOKEN && process.env.TELEGRAM_BOT_TOKEN !== 'ВАШ_ТОКЕН_БОТА_ЗДЕСЬ') {
  
  // ВАЖНО: 10808 — это пример порта. 
  // Если вы используете Hiddify, Nekoray или v2rayN, посмотрите в настройках вашего VPN, 
  // на каком порту у вас работает "SOCKS5" или "HTTP proxy", и впишите его сюда.
  const agent = new SocksProxyAgent('socks5://127.0.0.1:10808'); 
  
  const bot = new TelegramBot(process.env.TELEGRAM_BOT_TOKEN, { 
    polling: true,
    request: { agent } // Передаем прокси боту
  });
  
  // Обработка команды /start
  bot.onText(/\/start/, (msg) => {
    bot.sendMessage(msg.chat.id, `Привет! Ваш Chat ID: ${msg.chat.id}\n\nСкопируйте его и вставьте в настройках профиля на сайте.`);
  });

  // Проверка каждый день в 09:00 утра
  cron.schedule('* * * * *', () => {
    const today = new Date().toISOString().split('T')[0];
    db.all(`SELECT d.*, u.telegram_chat_id FROM deadlines d 
            JOIN users u ON d.user_id = u.id 
            WHERE d.end_date = ? AND u.telegram_chat_id IS NOT NULL`, [today], (err, rows) => {
      if (err) return console.error(err);
      rows.forEach(row => {
        bot.sendMessage(row.telegram_chat_id, `⚠️ Напоминание!\nСегодня последний день по дедлайну: *${row.title}*\n\n${row.description || ''}`, { parse_mode: 'Markdown' });
      });
    });
  });
}

// 👇 И только после этого идет запуск сервера 👇
app.listen(PORT, () => {
  console.log(`Сервер запущен на http://localhost:${PORT}`);
});

app.listen(PORT, () => {
  console.log(`Сервер запущен на http://localhost:${PORT}`);
});