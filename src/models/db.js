const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');

// Initialize database
const db = new Database(process.env.DB_PATH || path.join(__dirname, '../../data/messages.db'));

// Load schema
const schema = fs.readFileSync(path.join(__dirname, 'schema.sql'), 'utf8');
db.exec(schema);

// Prepare statements
const statements = {
  // Users
  createUser: db.prepare(`
    INSERT INTO users (id, username, public_key_kem, public_key_sig)
    VALUES (?, ?, ?, ?)
  `),
  getUser: db.prepare('SELECT * FROM users WHERE id = ?'),
  getUserByUsername: db.prepare('SELECT * FROM users WHERE username = ?'),

  // Messages
  createMessage: db.prepare(`
    INSERT INTO messages (id, sender_id, recipient_id, content, signature)
    VALUES (?, ?, ?, ?, ?)
  `),
  getMessages: db.prepare(`
    SELECT m.*, u.username as sender_username
    FROM messages m
    JOIN users u ON m.sender_id = u.id
    WHERE (m.sender_id = ? AND m.recipient_id = ?)
    OR (m.sender_id = ? AND m.recipient_id = ?)
    ORDER BY m.created_at DESC
    LIMIT ?
  `),
  markMessageAsRead: db.prepare(`
    UPDATE messages
    SET read_at = CURRENT_TIMESTAMP
    WHERE id = ? AND recipient_id = ?
  `),

  // Sessions
  createSession: db.prepare(`
    INSERT INTO sessions (id, user_id, shared_key, expires_at)
    VALUES (?, ?, ?, datetime('now', '+1 day'))
  `),
  getSession: db.prepare('SELECT * FROM sessions WHERE id = ? AND expires_at > datetime("now")'),
  deleteSession: db.prepare('DELETE FROM sessions WHERE id = ?')
};

module.exports = {
  db,
  ...statements
};
