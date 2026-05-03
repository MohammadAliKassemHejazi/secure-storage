const express        = require('express');
const session        = require('express-session');
const multer         = require('multer');
const bcrypt         = require('bcryptjs');
const speakeasy      = require('speakeasy');
const qrcode         = require('qrcode');
const crypto         = require('crypto');
const fs             = require('fs');
const path           = require('path');

const { init, db }             = require('./db');
const { encryptFile, decryptFile } = require('./crypto_utils');

// ── App setup ────────────────────────────────────────────────────────────────

const app    = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 50 * 1024 * 1024 } });

const UPLOAD_DIR = path.join(__dirname, 'encrypted_files');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { mode: 0o700 });

function getOrCreateSecret(file) {
  if (fs.existsSync(file)) return fs.readFileSync(file, 'utf8');
  const s = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(file, s, { mode: 0o600 });
  return s;
}

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.urlencoded({ extended: false }));
app.use(session({
  secret: getOrCreateSecret('.session_secret'),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'strict', maxAge: 8 * 60 * 60 * 1000 }
}));

// Expose session to all EJS templates
app.use((req, res, next) => {
  res.locals.sess     = req.session;
  res.locals.messages = consumeFlash(req);
  next();
});

// ── Helpers ──────────────────────────────────────────────────────────────────

function flash(req, type, msg) {
  (req.session.flash ??= []).push({ type, msg });
}

function consumeFlash(req) {
  const msgs = req.session.flash ?? [];
  req.session.flash = [];
  return msgs;
}

function audit(req, action, resource = null, details = null, success = true) {
  db.prepare(
    `INSERT INTO audit_logs (user_id, username, action, resource, ip_address, details, success)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(req.session.userId ?? null, req.session.username ?? null,
        action, resource, req.ip, details, success ? 1 : 0);
}

function sanitizeFilename(name) {
  return path.basename(name).replace(/[^\w.\-]/g, '_') || 'file';
}

// ── Middleware ────────────────────────────────────────────────────────────────

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId) return res.redirect('/login');
  const user = db.prepare('SELECT role FROM users WHERE id = ?').get(req.session.userId);
  if (user?.role !== 'admin') return res.status(403).send('Access denied.');
  next();
}

// ── Auth routes ───────────────────────────────────────────────────────────────

app.get('/register', (req, res) => res.render('register'));

app.post('/register', (req, res) => {
  const { username = '', password = '' } = req.body;

  if (username.trim().length < 3 || password.length < 8) {
    flash(req, 'error', 'Username must be at least 3 characters and password at least 8.');
    return res.redirect('/register');
  }
  if (db.prepare('SELECT id FROM users WHERE username = ?').get(username)) {
    flash(req, 'error', 'Username already taken.');
    return res.redirect('/register');
  }

  const role = db.prepare('SELECT COUNT(*) AS c FROM users').get().c === 0 ? 'admin' : 'user';
  const hash = bcrypt.hashSync(password, 12);
  const { lastInsertRowid } = db.prepare(
    'INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)'
  ).run(username.trim(), hash, role);

  db.prepare(
    `INSERT INTO audit_logs (user_id, username, action, ip_address, details, success)
     VALUES (?, ?, 'REGISTER', ?, ?, 1)`
  ).run(lastInsertRowid, username, req.ip, `Role: ${role}`);

  flash(req, 'success', 'Account created. Please log in.');
  res.redirect('/login');
});

app.get('/login', (req, res) => res.render('login'));

app.post('/login', (req, res) => {
  const { username = '', password = '' } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    db.prepare(
      `INSERT INTO audit_logs (username, action, ip_address, details, success)
       VALUES (?, 'LOGIN_FAIL', ?, 'Bad credentials', 0)`
    ).run(username, req.ip);
    flash(req, 'error', 'Invalid username or password.');
    return res.redirect('/login');
  }

  if (user.mfa_enabled) {
    req.session.mfaPendingUserId = user.id;
    return res.redirect('/verify-mfa');
  }

  req.session.regenerate(() => {
    req.session.userId   = user.id;
    req.session.username = user.username;
    req.session.role     = user.role;
    db.prepare(
      `INSERT INTO audit_logs (user_id, username, action, ip_address, success)
       VALUES (?, ?, 'LOGIN', ?, 1)`
    ).run(user.id, user.username, req.ip);
    res.redirect('/');
  });
});

app.get('/verify-mfa', (req, res) => {
  if (!req.session.mfaPendingUserId) return res.redirect('/login');
  res.render('verify_mfa');
});

app.post('/verify-mfa', (req, res) => {
  const pendingId = req.session.mfaPendingUserId;
  if (!pendingId) return res.redirect('/login');

  const user  = db.prepare('SELECT * FROM users WHERE id = ?').get(pendingId);
  const valid = speakeasy.totp.verify({
    secret: user.mfa_secret, encoding: 'base32',
    token: req.body.code ?? '', window: 1
  });

  if (!valid) {
    db.prepare(
      `INSERT INTO audit_logs (user_id, username, action, ip_address, success)
       VALUES (?, ?, 'MFA_FAIL', ?, 0)`
    ).run(user.id, user.username, req.ip);
    flash(req, 'error', 'Invalid MFA code. Try again.');
    return res.redirect('/verify-mfa');
  }

  req.session.regenerate(() => {
    req.session.userId   = user.id;
    req.session.username = user.username;
    req.session.role     = user.role;
    db.prepare(
      `INSERT INTO audit_logs (user_id, username, action, ip_address, success)
       VALUES (?, ?, 'LOGIN_MFA', ?, 1)`
    ).run(user.id, user.username, req.ip);
    res.redirect('/');
  });
});

app.get('/logout', (req, res) => {
  audit(req, 'LOGOUT');
  req.session.destroy(() => res.redirect('/login'));
});

// ── File routes ───────────────────────────────────────────────────────────────

app.get('/', requireAuth, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  const files = user.role === 'admin'
    ? db.prepare(
        `SELECT f.*, u.username AS owner_name FROM files f
         JOIN users u ON f.owner_id = u.id ORDER BY f.uploaded_at DESC`
      ).all()
    : db.prepare(
        `SELECT f.*, u.username AS owner_name FROM files f
         JOIN users u ON f.owner_id = u.id
         WHERE f.owner_id = ? ORDER BY f.uploaded_at DESC`
      ).all(user.id);
  res.render('dashboard', { user, files });
});

app.post('/upload', requireAuth, upload.single('file'), (req, res) => {
  if (!req.file) {
    flash(req, 'error', 'No file selected.');
    return res.redirect('/');
  }

  const fileId     = crypto.randomUUID();
  const { blob, fileHash } = encryptFile(req.file.buffer, fileId);
  const storedName = `${fileId}.enc`;

  fs.writeFileSync(path.join(UPLOAD_DIR, storedName), blob, { mode: 0o600 });
  db.prepare(
    'INSERT INTO files (id, original_name, stored_name, owner_id, file_hash, file_size) VALUES (?,?,?,?,?,?)'
  ).run(fileId, sanitizeFilename(req.file.originalname), storedName,
        req.session.userId, fileHash, req.file.size);

  audit(req, 'UPLOAD', req.file.originalname, `${req.file.size} bytes`);
  flash(req, 'success', 'File uploaded and encrypted with AES-256-GCM.');
  res.redirect('/');
});

app.get('/download/:id', requireAuth, (req, res) => {
  const record = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (!record) return res.status(404).send('File not found.');
  if (req.session.role !== 'admin' && record.owner_id !== req.session.userId) {
    audit(req, 'DOWNLOAD_DENIED', req.params.id, null, false);
    return res.status(403).send('Access denied.');
  }

  const blob = fs.readFileSync(path.join(UPLOAD_DIR, record.stored_name));
  let plaintext;
  try {
    plaintext = decryptFile(blob, record.id);
  } catch {
    audit(req, 'DECRYPT_FAIL', record.original_name, null, false);
    flash(req, 'error', 'Decryption failed — file may be corrupted.');
    return res.redirect('/');
  }

  const actualHash = crypto.createHash('sha256').update(plaintext).digest('hex');
  if (actualHash !== record.file_hash) {
    audit(req, 'INTEGRITY_FAIL', record.original_name, null, false);
    flash(req, 'error', 'Integrity check FAILED — file may have been tampered with.');
    return res.redirect('/');
  }

  audit(req, 'DOWNLOAD', record.original_name);
  res.setHeader('Content-Disposition', `attachment; filename="${record.original_name}"`);
  res.send(plaintext);
});

app.post('/delete/:id', requireAuth, (req, res) => {
  const record = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.id);
  if (!record) return res.status(404).send('File not found.');
  if (req.session.role !== 'admin' && record.owner_id !== req.session.userId) {
    audit(req, 'DELETE_DENIED', req.params.id, null, false);
    return res.status(403).send('Access denied.');
  }

  const filePath = path.join(UPLOAD_DIR, record.stored_name);
  if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  db.prepare('DELETE FROM files WHERE id = ?').run(record.id);

  audit(req, 'DELETE', record.original_name);
  flash(req, 'success', 'File deleted.');
  res.redirect('/');
});

// ── MFA setup ─────────────────────────────────────────────────────────────────

app.get('/setup-mfa', requireAuth, async (req, res) => {
  const user   = db.prepare('SELECT username FROM users WHERE id = ?').get(req.session.userId);
  const secret = speakeasy.generateSecret({ name: `SecureVault (${user.username})`, length: 20 });
  req.session.mfaSetupSecret = secret.base32;
  const qrDataUrl = await qrcode.toDataURL(secret.otpauth_url);
  res.render('mfa_setup', { qrDataUrl, manualSecret: secret.base32 });
});

app.post('/confirm-mfa', requireAuth, (req, res) => {
  const secret = req.session.mfaSetupSecret;
  if (!secret) return res.redirect('/');

  const valid = speakeasy.totp.verify({ secret, encoding: 'base32', token: req.body.code ?? '', window: 1 });
  if (valid) {
    db.prepare('UPDATE users SET mfa_secret = ?, mfa_enabled = 1 WHERE id = ?')
      .run(secret, req.session.userId);
    delete req.session.mfaSetupSecret;
    audit(req, 'MFA_ENABLED');
    flash(req, 'success', 'MFA enabled successfully.');
  } else {
    flash(req, 'error', 'Invalid code — MFA not enabled. Try again.');
  }
  res.redirect('/');
});

app.post('/disable-mfa', requireAuth, (req, res) => {
  db.prepare('UPDATE users SET mfa_secret = NULL, mfa_enabled = 0 WHERE id = ?')
    .run(req.session.userId);
  audit(req, 'MFA_DISABLED');
  flash(req, 'success', 'MFA disabled.');
  res.redirect('/');
});

// ── Audit log (admin) ─────────────────────────────────────────────────────────

app.get('/audit', requireAdmin, (req, res) => {
  const logs = db.prepare('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT 500').all();
  res.render('audit', { logs });
});

// ── Start ─────────────────────────────────────────────────────────────────────

(async () => {
  await init();
  app.listen(3000, '127.0.0.1', () => {
    console.log('SecureVault running at http://127.0.0.1:3000');
  });
})();
