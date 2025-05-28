import os
import sqlite3
import datetime

# Database file path
DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'backend_database.sqlite')

def check_column_exists(cursor, table, column):
    """Check if a column exists in a table"""
    cursor.execute(f"PRAGMA table_info({table})")
    columns = [info[1] for info in cursor.fetchall()]
    return column in columns

def init_db():
    """Initialize the database with required tables"""
    print(f"Initializing database at {DB_FILE}")
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create users table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        email TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        kem_public_key TEXT,
        kem_private_key TEXT,
        dss_public_key TEXT,
        dss_private_key TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    
    # Create sessions table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        username TEXT NOT NULL,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
        expires_at TEXT NOT NULL,
        FOREIGN KEY (username) REFERENCES users(username)
    )
    ''')
    
    # Check if messages table exists
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'")
    messages_exists = cursor.fetchone() is not None
    
    if not messages_exists:
        # Create messages table if it doesn't exist
        cursor.execute('''
        CREATE TABLE messages (
            id TEXT PRIMARY KEY,
            sender_username TEXT NOT NULL,
            recipient_username TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            signature TEXT,
            client_message_id TEXT,
            is_read INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        print("Created new messages table")
    else:
        print("Messages table already exists, checking columns...")
        
        # Check if necessary columns exist and add them if they don't
        if not check_column_exists(cursor, 'messages', 'client_message_id'):
            print("Adding client_message_id column to messages table")
            cursor.execute("ALTER TABLE messages ADD COLUMN client_message_id TEXT")
        
        if not check_column_exists(cursor, 'messages', 'is_read'):
            print("Adding is_read column to messages table")
            cursor.execute("ALTER TABLE messages ADD COLUMN is_read INTEGER DEFAULT 0")
        
        if not check_column_exists(cursor, 'messages', 'signature'):
            print("Adding signature column to messages table")
            cursor.execute("ALTER TABLE messages ADD COLUMN signature TEXT")
        
        if not check_column_exists(cursor, 'messages', 'created_at'):
            print("Adding created_at column to messages table")
            # SQLite doesn't support adding columns with DEFAULT CURRENT_TIMESTAMP
            # So we add the column without a default and then update existing rows
            cursor.execute("ALTER TABLE messages ADD COLUMN created_at TEXT")
            cursor.execute("UPDATE messages SET created_at = datetime('now') WHERE created_at IS NULL")
    
    # Create indexes if they don't exist
    try:
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_sender_recipient ON messages (sender_username, recipient_username)')
        print("Created or verified sender_recipient index")
    except sqlite3.OperationalError as e:
        print(f"Error creating sender_recipient index: {e}")
    
    try:
        if check_column_exists(cursor, 'messages', 'client_message_id'):
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_client_message_id ON messages (client_message_id)')
            print("Created or verified client_message_id index")
    except sqlite3.OperationalError as e:
        print(f"Error creating client_message_id index: {e}")
    
    try:
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON messages (timestamp)')
        print("Created or verified timestamp index")
    except sqlite3.OperationalError as e:
        print(f"Error creating timestamp index: {e}")
    
    conn.commit()
    
    # Check if tables were created successfully
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    print(f"Database tables: {', '.join([t[0] for t in tables])}")
    
    # Check if we have any users
    cursor.execute("SELECT COUNT(*) FROM users")
    user_count = cursor.fetchone()[0]
    print(f"User count: {user_count}")
    
    # Check if we have any messages
    cursor.execute("SELECT COUNT(*) FROM messages")
    message_count = cursor.fetchone()[0]
    print(f"Message count: {message_count}")
    
    conn.close()
    print("Database initialization complete")

if __name__ == "__main__":
    init_db()
