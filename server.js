require('dotenv').config();
const express = require('express');
const cors = require('cors');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');

const PORT = process.env.PORT || 3000;
const DB_PATH = path.join(__dirname, 'contacts.db');

// init db
const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS contacts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT,
      message TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
  );
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      email TEXT UNIQUE,
      password_hash TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`
  );
});

const app = express();
app.use(cors());
app.use(express.json());

// simple health
app.get('/api/health', (req, res) => res.json({ ok: true }));

app.post('/api/contact', async (req, res) => {
  const { name, email, message } = req.body || {};
  if (!email || !message) return res.status(400).json({ error: 'email and message are required' });

  // store in db
  const stmt = db.prepare('INSERT INTO contacts (name,email,message) VALUES (?,?,?)');
  stmt.run(name || '', email, message, function (err) {
    if (err) {
      console.error('DB insert error', err);
      return res.status(500).json({ error: 'db_error' });
    }

    const insertedId = this.lastID;
    // attempt to send email only if SMTP credentials are present
    const smtpUser = process.env.GMAIL_USER;
    const smtpPass = process.env.GMAIL_PASS;
    if (smtpUser && smtpPass) {
      sendNotificationEmail({ id: insertedId, name, email, message })
        .then(() => res.json({ ok: true, stored: true, emailed: true }))
        .catch((err) => {
          console.error('email error', err);
          // still return success for storage, but indicate email failed
          res.status(200).json({ ok: true, stored: true, emailed: false, error: 'email_error' });
        });
    } else {
      console.warn('SMTP not configured: message stored but not emailed');
      res.json({ ok: true, stored: true, emailed: false, note: 'SMTP not configured on server' });
    }
  });
  stmt.finalize();
});

// Signup endpoint
app.post('/api/signup', async (req, res) => {
  try {
    const { name, email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    // check existing
    db.get('SELECT id FROM users WHERE email = ?', [email], (err, row) => {
      if (err) return res.status(500).json({ error: 'db_error' });
      if (row) return res.status(409).json({ error: 'user_exists' });

      const salt = bcrypt.genSaltSync(10);
      const hash = bcrypt.hashSync(password, salt);

      const stmt = db.prepare('INSERT INTO users (name,email,password_hash) VALUES (?,?,?)');
      stmt.run(name || '', email, hash, function (err) {
        if (err) return res.status(500).json({ error: 'db_error' });
        const id = this.lastID;
        res.json({ ok: true, user: { id, email, name: name || '' } });
      });
      stmt.finalize();
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

// Login endpoint
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: 'email and password required' });

    db.get('SELECT id,name,email,password_hash FROM users WHERE email = ?', [email], (err, user) => {
      if (err) return res.status(500).json({ error: 'db_error' });
      if (!user) return res.status(401).json({ error: 'invalid_credentials' });

      const valid = bcrypt.compareSync(password, user.password_hash || '');
      if (!valid) return res.status(401).json({ error: 'invalid_credentials' });

      // simple response (no token for demo)
      res.json({ ok: true, user: { id: user.id, email: user.email, name: user.name } });
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'server_error' });
  }
});

async function sendNotificationEmail({ id, name, email, message }) {
  const user = process.env.GMAIL_USER;
  const pass = process.env.GMAIL_PASS; // app password
  const target = process.env.TARGET_EMAIL || user || 'amansuman1100@gmail.com';

  if (!user || !pass) {
    console.warn('sendNotificationEmail: SMTP credentials not configured; skipping email send');
    return Promise.resolve(false);
  }

  const transport = nodemailer.createTransport({
    service: 'gmail',
    auth: { user, pass }
  });

  const html = `
    <p>New contact submission (id: ${id})</p>
    <p><strong>Name:</strong> ${escapeHtml(name || '')}</p>
    <p><strong>Email:</strong> ${escapeHtml(email)}</p>
    <p><strong>Message:</strong><br/>${escapeHtml(message).replace(/\n/g, '<br/>')}</p>
    <p>Stored in local SQLite database at <code>Bootstrap/contacts.db</code></p>
  `;

  await transport.sendMail({
    from: user,
    to: target,
    subject: `New contact from ${email}`,
    html
  });
}

function escapeHtml(str) {
  return String(str || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

app.listen(PORT, () => console.log(`Contact API listening on http://localhost:${PORT}`));
