/**
 * SQLite via sql.js (pure WASM — no native compilation needed).
 *
 * Exports:
 *   init()  — async, must be awaited before any db call
 *   db      — object with prepare(sql) returning { run, get, all }
 *             mimicking the better-sqlite3 synchronous API
 */

const initSqlJs = require('sql.js');
const fs        = require('fs');

const DB_FILE = 'secure_storage.db';
let _db = null;

function _save() {
  fs.writeFileSync(DB_FILE, Buffer.from(_db.export()));
}

async function init() {
  const SQL = await initSqlJs();
  _db = fs.existsSync(DB_FILE)
    ? new SQL.Database(fs.readFileSync(DB_FILE))
    : new SQL.Database();

  _db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT    UNIQUE NOT NULL,
      password_hash TEXT    NOT NULL,
      role          TEXT    NOT NULL DEFAULT 'user',
      mfa_secret    TEXT,
      mfa_enabled   INTEGER NOT NULL DEFAULT 0,
      created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS files (
      id            TEXT    PRIMARY KEY,
      original_name TEXT    NOT NULL,
      stored_name   TEXT    NOT NULL,
      owner_id      INTEGER NOT NULL REFERENCES users(id),
      file_hash     TEXT    NOT NULL,
      file_size     INTEGER NOT NULL,
      uploaded_at   TEXT    NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS audit_logs (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id     INTEGER,
      username    TEXT,
      action      TEXT NOT NULL,
      resource    TEXT,
      ip_address  TEXT,
      timestamp   TEXT NOT NULL DEFAULT (datetime('now')),
      details     TEXT,
      success     INTEGER NOT NULL DEFAULT 1
    );
  `);
  _save();
}

const db = {
  prepare(sql) {
    return {
      run(...args) {
        const stmt = _db.prepare(sql);
        stmt.bind(args);
        stmt.step();
        stmt.free();
        _save();
        const res = _db.exec('SELECT last_insert_rowid()');
        return { lastInsertRowid: res[0]?.values[0][0] ?? null };
      },
      get(...args) {
        const stmt = _db.prepare(sql);
        stmt.bind(args);
        const row = stmt.step() ? stmt.getAsObject() : undefined;
        stmt.free();
        return row;
      },
      all(...args) {
        const stmt = _db.prepare(sql);
        stmt.bind(args);
        const rows = [];
        while (stmt.step()) rows.push(stmt.getAsObject());
        stmt.free();
        return rows;
      },
    };
  },
};

module.exports = { init, db };
