require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const crypto = require('crypto');
const path = require('path');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ---------- MySQL ----------
const cfg = {
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
};
const DB_NAME = process.env.DB_NAME || 'student_registration';
let pool;

async function initDb() {
  try {
    const c = await mysql.createConnection(cfg);
    await c.query(`CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\``);
    await c.end();
  } catch (e) { console.log('Skipping CREATE DATABASE:', e.message); }

  pool = mysql.createPool({ ...cfg, database: DB_NAME, timezone: 'Z', connectionLimit: 10 });

  await pool.query(`CREATE TABLE IF NOT EXISTS registrations (
    id INT AUTO_INCREMENT PRIMARY KEY,
    full_name VARCHAR(150) NOT NULL,
    dob DATE NOT NULL,
    father_name VARCHAR(150) NOT NULL,
    mother_name VARCHAR(150) NOT NULL,
    student_mobile VARCHAR(15) NOT NULL,
    parent_mobile VARCHAR(15) NOT NULL,
    current_place VARCHAR(150) NOT NULL,
    email VARCHAR(190) NOT NULL,
    reg_no VARCHAR(30) NOT NULL,
    password_hash VARCHAR(200) NOT NULL,
    registered_at DATETIME NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'Pending',
    reject_reason VARCHAR(255) NULL,
    reset_token_hash VARCHAR(64) NULL,
    reset_expires DATETIME NULL,
    UNIQUE KEY uq_email (email),
    UNIQUE KEY uq_regno (reg_no)
  )`);

  for (const sql of [
    "ALTER TABLE registrations ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'Pending'",
    "ALTER TABLE registrations ADD COLUMN reject_reason VARCHAR(255) NULL",
    "ALTER TABLE registrations ADD COLUMN reset_token_hash VARCHAR(64) NULL",
    "ALTER TABLE registrations ADD COLUMN reset_expires DATETIME NULL",
  ]) {
    try { await pool.query(sql); } catch (e) { if (e.code !== 'ER_DUP_FIELDNAME') throw e; }
  }
}

// ---------- helpers ----------
const genRegNo = () => `REG${new Date().getFullYear()}${crypto.randomInt(100000, 999999)}`;
const genPassword = () => {
  const c = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789';
  return Array.from({ length: 8 }, () => c[crypto.randomInt(c.length)]).join('');
};
const mobileOk = (m) => /^[6-9]\d{9}$/.test(m);
const emailOk = (e) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const mask = (n) => n.trim().split(/\s+/).map((w) => w[0] + '***').join(' ');

async function verifyPassword(plain, stored) {
  if (stored.startsWith('$2')) return bcrypt.compare(plain, stored);
  const [salt, hash] = stored.split(':');
  if (!salt || !hash) return false;
  const test = crypto.scryptSync(plain, salt, 32).toString('hex');
  const a = Buffer.from(test), b = Buffer.from(hash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const hashPassword = (p) => bcrypt.hash(p, 10);

// ---------- email ---------
// ---------- email (via Resend API) ----------
const mailReady = !!process.env.RESEND_API_KEY;

async function sendMail(to, subject, html) {
  if (!mailReady) { console.log(`[email skipped - not configured] to=${to} subject="${subject}"`); return; }
  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.RESEND_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'Student Registration <onboarding@resend.dev>',
        to: [to],
        subject,
        html,
      }),
    });
    if (!res.ok) {
      const errText = await res.text();
      console.error('Email send failed:', res.status, errText);
    }
  } catch (e) {
    console.error('Email send failed:', e.message);
  }
}

const wrap = (title, bodyHtml) => `
  <div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;border:1px solid #d8d3c4;border-radius:10px;overflow:hidden">
    <div style="background:#1f6f5c;color:#fff;padding:18px 22px;font-size:1.1rem;font-weight:700">${title}</div>
    <div style="padding:22px;color:#152238;line-height:1.6">${bodyHtml}</div>
  </div>`;

// ---------- session helpers ----------
const SECRET = process.env.SESSION_SECRET || 'change-this-secret';
const sign = (v) => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
const makeToken = (payload, hours) => {
  const exp = String(Date.now() + hours * 3600 * 1000);
  const body = payload + '.' + exp;
  return Buffer.from(body).toString('base64') + '.' + sign(body);
};
const readToken = (t) => {
  if (!t) return null;
  const [b64, sig] = t.split('.').length === 2 ? t.split('.') : [null, null];
  if (!b64 || !sig) return null;
  const body = Buffer.from(b64, 'base64').toString();
  const a = Buffer.from(sig), b = Buffer.from(sign(body));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const [payload, exp] = body.split('.');
  if (Number(exp) < Date.now()) return null;
  return payload;
};
const getCookie = (req, name) => {
  const m = (req.headers.cookie || '').split(';').map((s) => s.trim()).find((s) => s.startsWith(name + '='));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : '';
};
const setCookie = (res, name, value, hours) => {
  const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${name}=${value}; HttpOnly; Path=/; Max-Age=${hours * 3600}; SameSite=Strict${secure}`);
};
const clearCookie = (res, name) => {
  res.setHeader('Set-Cookie', `${name}=; HttpOnly; Path=/; Max-Age=0; SameSite=Strict`);
};

const requireAdmin = (req, res, next) => {
  const p = readToken(getCookie(req, 'admin_token'));
  if (p !== 'admin') return res.status(401).json({ error: 'Admin login required.' });
  next();
};
const requireStudent = (req, res, next) => {
  const id = readToken(getCookie(req, 'student_token'));
  if (!id) return res.status(401).json({ error: 'Please log in.' });
  req.studentId = id;
  next();
};

const fails = new Map();
const tooManyAttempts = (key) => {
  const rec = fails.get(key) || { n: 0, t: Date.now() };
  return rec.n >= 5 && Date.now() - rec.t < 10 * 60 * 1000;
};
const recordFail = (key) => { const r = fails.get(key) || { n: 0, t: Date.now() }; fails.set(key, { n: r.n + 1, t: Date.now() }); };
const clearFails = (key) => fails.delete(key);

const h = (s) => crypto.createHash('sha256').update(String(s)).digest();
const constEq = (a, b) => { try { return crypto.timingSafeEqual(h(a), h(b)); } catch { return false; } };

// ===================== ADMIN AUTH =====================
app.post('/api/admin/login', (req, res) => {
  if (!process.env.ADMIN_PASSWORD) return res.status(500).json({ error: 'ADMIN_PASSWORD is not set in .env' });
  const key = 'admin:' + req.ip;
  if (tooManyAttempts(key)) return res.status(429).json({ error: 'Too many attempts. Try again after 10 minutes.' });
  const { username = '', password = '' } = req.body || {};
  const ok = constEq(username, process.env.ADMIN_USER || 'admin') && constEq(password, process.env.ADMIN_PASSWORD);
  if (!ok) { recordFail(key); return res.status(401).json({ error: 'Wrong username or password.' }); }
  clearFails(key);
  setCookie(res, 'admin_token', makeToken('admin', 8), 8);
  res.json({ ok: true });
});
app.post('/api/admin/logout', (req, res) => { clearCookie(res, 'admin_token'); res.json({ ok: true }); });

// ===================== STUDENT AUTH =====================
app.post('/api/student/login', async (req, res) => {
  const key = 'student:' + req.ip;
  if (tooManyAttempts(key)) return res.status(429).json({ error: 'Too many attempts. Try again after 10 minutes.' });
  const { regNo = '', password = '' } = req.body || {};
  if (!regNo.trim() || !password) return res.status(400).json({ error: 'Enter Registration Number and Password.' });

  const [rows] = await pool.query('SELECT id, password_hash FROM registrations WHERE reg_no = ?', [regNo.trim()]);
  if (!rows.length) { recordFail(key); return res.status(401).json({ error: 'Invalid Registration Number or Password.' }); }

  const student = rows[0];
  const valid = await verifyPassword(password, student.password_hash);
  if (!valid) { recordFail(key); return res.status(401).json({ error: 'Invalid Registration Number or Password.' }); }

  if (!student.password_hash.startsWith('$2')) {
    const newHash = await hashPassword(password);
    await pool.query('UPDATE registrations SET password_hash = ? WHERE id = ?', [newHash, student.id]);
  }

  clearFails(key);
  setCookie(res, 'student_token', makeToken(String(student.id), 8), 8);
  res.json({ ok: true });
});
app.post('/api/student/logout', (req, res) => { clearCookie(res, 'student_token'); res.json({ ok: true }); });

app.get('/api/student/me', requireStudent, async (req, res) => {
  const [rows] = await pool.query(
    `SELECT full_name, reg_no, email, current_place, status, reject_reason, registered_at
     FROM registrations WHERE id = ?`, [req.studentId]);
  if (!rows.length) return res.status(404).json({ error: 'Not found.' });
  res.json(rows[0]);
});

// ===================== REGISTRATION =====================
app.post('/api/register', async (req, res) => {
  try {
    const b = req.body || {};
    const f = ['fullName', 'dob', 'fatherName', 'motherName', 'studentMobile', 'parentMobile', 'currentPlace', 'email'];
    if (f.some((k) => !String(b[k] || '').trim()))
      return res.status(400).json({ error: 'All fields are required.' });
    if (!emailOk(b.email.trim())) return res.status(400).json({ error: 'Enter a valid email.' });
    if (!mobileOk(b.studentMobile) || !mobileOk(b.parentMobile))
      return res.status(400).json({ error: 'Mobile numbers must be 10 digits.' });
    if (new Date(b.dob) > new Date()) return res.status(400).json({ error: 'Invalid date of birth.' });

    const email = b.email.trim().toLowerCase();
    const password = genPassword();
    const passwordHash = await hashPassword(password);
    const now = new Date();

    for (let i = 0; i < 5; i++) {
      const regNo = genRegNo();
      try {
        await pool.query(
          `INSERT INTO registrations (full_name, dob, father_name, mother_name, student_mobile,
           parent_mobile, current_place, email, reg_no, password_hash, registered_at)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
          [b.fullName.trim(), b.dob, b.fatherName.trim(), b.motherName.trim(), b.studentMobile,
           b.parentMobile, b.currentPlace.trim(), email, regNo, passwordHash, now]
        );

        sendMail(email, 'Registration Received', wrap('Registration Received',
          `<p>Hi ${b.fullName.trim()},</p>
           <p>Your registration was received successfully.</p>
           <p><b>Registration Number:</b> ${regNo}<br><b>Status:</b> Pending review</p>
           <p>You can log in anytime with your Registration Number and Password to check your status.</p>`));

        return res.status(201).json({ name: b.fullName.trim(), regNo, password, registeredAt: now.toISOString(), status: 'Pending' });
      } catch (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          if (err.sqlMessage.includes('uq_email'))
            return res.status(409).json({ error: 'This email already exists. Only one registration per email is allowed.' });
          continue;
        }
        throw err;
      }
    }
    res.status(500).json({ error: 'Please try again.' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Server error. Please try again later.' });
  }
});

// ===================== FORGOT / RESET PASSWORD =====================
app.post('/api/forgot-password', async (req, res) => {
  const email = String((req.body || {}).email || '').trim().toLowerCase();
  const generic = { ok: true, message: 'If that email is registered, a reset link has been sent.' };
  if (!emailOk(email)) return res.json(generic);

  const [rows] = await pool.query('SELECT id, full_name FROM registrations WHERE email = ?', [email]);
  if (rows.length) {
    const student = rows[0];
    const rawToken = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(rawToken).digest('hex');
    const expires = new Date(Date.now() + 30 * 60 * 1000);
    await pool.query('UPDATE registrations SET reset_token_hash = ?, reset_expires = ? WHERE id = ?',
      [tokenHash, expires, student.id]);

    const link = `${process.env.APP_URL || 'http://localhost:3000'}/reset-password.html?token=${rawToken}&id=${student.id}`;
    sendMail(email, 'Reset Your Password', wrap('Reset Your Password',
      `<p>Hi ${student.full_name},</p>
       <p>Click the button below to reset your password. This link expires in 30 minutes.</p>
       <p><a href="${link}" style="display:inline-block;background:#1f6f5c;color:#fff;padding:10px 18px;border-radius:6px;text-decoration:none">Reset Password</a></p>
       <p>If you did not request this, you can ignore this email.</p>`));
  }
  res.json(generic);
});

app.post('/api/reset-password', async (req, res) => {
  const { id, token, newPassword } = req.body || {};
  if (!id || !token || !newPassword || newPassword.length < 6)
    return res.status(400).json({ error: 'Password must be at least 6 characters.' });

  const [rows] = await pool.query('SELECT reset_token_hash, reset_expires FROM registrations WHERE id = ?', [id]);
  if (!rows.length || !rows[0].reset_token_hash) return res.status(400).json({ error: 'Invalid or expired link.' });

  const { reset_token_hash, reset_expires } = rows[0];
  if (!reset_expires || new Date(reset_expires) < new Date()) return res.status(400).json({ error: 'This link has expired. Please request a new one.' });

  const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex');
  const a = Buffer.from(tokenHash), b = Buffer.from(reset_token_hash);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return res.status(400).json({ error: 'Invalid or expired link.' });

  const newHash = await hashPassword(newPassword);
  await pool.query('UPDATE registrations SET password_hash = ?, reset_token_hash = NULL, reset_expires = NULL WHERE id = ?', [newHash, id]);
  res.json({ ok: true });
});

// ===================== PUBLIC LIST (masked) =====================
app.get('/api/public-list', async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT full_name, registered_at FROM registrations ORDER BY id DESC');
    res.json({ total: rows.length, list: rows.map((r) => ({ name: mask(r.full_name), registeredAt: r.registered_at })) });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error.' }); }
});

// ===================== ADMIN ONLY =====================
app.get('/api/admin/registrations', requireAdmin, async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, full_name, dob, father_name, mother_name, student_mobile, parent_mobile,
              current_place, email, reg_no, status, reject_reason, registered_at
       FROM registrations ORDER BY id DESC`);
    res.json(rows);
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error.' }); }
});

app.post('/api/admin/status', requireAdmin, async (req, res) => {
  try {
    const { id, status, reason } = req.body || {};
    if (!['Approved', 'Rejected'].includes(status)) return res.status(400).json({ error: 'Invalid status.' });
    if (status === 'Rejected' && !String(reason || '').trim())
      return res.status(400).json({ error: 'Rejection reason is required.' });

    await pool.query('UPDATE registrations SET status = ?, reject_reason = ? WHERE id = ?',
      [status, status === 'Rejected' ? String(reason).trim().slice(0, 255) : null, id]);

    const [rows] = await pool.query('SELECT full_name, email, reg_no FROM registrations WHERE id = ?', [id]);
    if (rows.length) {
      const s = rows[0];
      if (status === 'Approved') {
               sendMail(email, 'Registration Received', wrap('Registration Received',
          `<p>Hi ${b.fullName.trim()},</p>
           <p>Your registration was received successfully.</p>
           <p><b>Registration Number:</b> ${regNo}<br>
              <b>Password:</b> ${password}<br>
              <b>Status:</b> Pending review</p>
           <p>Please save this email safely. You can log in anytime at
              <a href="${process.env.APP_URL || 'http://localhost:3000'}/student-login.html">Student Login</a>
              using your Registration Number and Password to check your status.</p>
           <p style="color:#a1372c;font-size:.85rem">Do not share this password with anyone.</p>`));
      }
    }
    res.json({ ok: true });
  } catch (e) { console.error(e); res.status(500).json({ error: 'Server error.' }); }
});

initDb()
  .then(() => app.listen(process.env.PORT || 3000, () => {
    console.log(`Running at http://localhost:${process.env.PORT || 3000}`);
    if (!mailReady) console.log('Note: EMAIL_USER / EMAIL_PASS not set in .env - emails will be skipped, not sent.');
  }))
  .catch((e) => { console.error('Database connection failed:', e.message); process.exit(1); });