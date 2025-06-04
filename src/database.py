import sqlite3
import json
import os
import datetime
from typing import List, Dict, Any, Optional, Tuple

# Database file path - configurable for different environments
DATABASE_PATH = os.environ.get('DATABASE_PATH')

# If DATABASE_PATH is not set, use the default path
if not DATABASE_PATH:
    # For local development
    DB_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'backend_database.sqlite')
else:
    # For production deployment (Render)
    DB_FILE = DATABASE_PATH
    
    # Ensure the directory exists
    os.makedirs(os.path.dirname(DB_FILE), exist_ok=True)
    
    print(f"Using database at: {DB_FILE}")


def get_db_connection():
    """Create a connection to the SQLite database"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row  # This enables column access by name
    return conn

def init_db():
    """Initialize the database with required tables if they don't exist"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create messages table if it doesn't exist
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS messages (
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
    
    # Create index on sender and recipient for faster queries
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_sender_recipient ON messages (sender_username, recipient_username)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_client_message_id ON messages (client_message_id)')
    
    conn.commit()
    conn.close()
    
    print("Database initialized with messages table")

def save_message(message_data: Dict[str, Any]) -> str:
    """
    Save a message to the database
    
    Args:
        message_data: Dictionary containing message data
        
    Returns:
        The ID of the saved message
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Generate a unique ID if not provided
    if 'id' not in message_data:
        message_data['id'] = f"msg_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{os.urandom(4).hex()}"
    
    # Ensure timestamp is in ISO format
    if 'timestamp' not in message_data:
        message_data['timestamp'] = datetime.datetime.now().isoformat()
    
    # Extract required fields
    message_id = message_data['id']
    sender = message_data['sender_username']
    recipient = message_data['recipient_username']
    content = message_data['content']
    timestamp = message_data['timestamp']
    
    # Optional fields
    signature = message_data.get('signature', '')
    client_message_id = message_data.get('client_message_id', '')
    is_read = message_data.get('is_read', 0)
    
    try:
        # Check if message with this ID or client_message_id already exists
        if client_message_id:
            cursor.execute('SELECT id FROM messages WHERE client_message_id = ?', (client_message_id,))
            existing = cursor.fetchone()
            if existing:
                print(f"Message with client_message_id {client_message_id} already exists, skipping")
                return existing['id']
        
        # Insert the message
        cursor.execute('''
        INSERT INTO messages (id, sender_username, recipient_username, content, timestamp, signature, client_message_id, is_read)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (message_id, sender, recipient, content, timestamp, signature, client_message_id, is_read))
        
        conn.commit()
        print(f"Message saved with ID: {message_id}")
        return message_id
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()

def get_messages_for_user(username: str, other_username: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """
    Get messages for a specific user, optionally filtered by conversation partner
    
    Args:
        username: The username to get messages for
        other_username: Optional username of the conversation partner
        limit: Maximum number of messages to return
        
    Returns:
        List of message dictionaries
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        if other_username:
            # Get messages between two specific users
            cursor.execute('''
            SELECT * FROM messages 
            WHERE (sender_username = ? AND recipient_username = ?) 
               OR (sender_username = ? AND recipient_username = ?)
            ORDER BY timestamp ASC
            LIMIT ?
            ''', (username, other_username, other_username, username, limit))
        else:
            # Get all messages for this user
            cursor.execute('''
            SELECT * FROM messages 
            WHERE sender_username = ? OR recipient_username = ?
            ORDER BY timestamp ASC
            LIMIT ?
            ''', (username, username, limit))
        
        # Convert rows to dictionaries
        messages = []
        for row in cursor.fetchall():
            message = dict(row)
            # Add a flag to indicate if this message is outgoing (sent by the user)
            message['isOutgoing'] = (message['sender_username'] == username)
            messages.append(message)
        
        return messages
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []
    finally:
        conn.close()

def mark_messages_as_read(username: str, other_username: str) -> int:
    """
    Mark all messages from other_username to username as read
    
    Args:
        username: The recipient username
        other_username: The sender username
        
    Returns:
        Number of messages marked as read
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
        UPDATE messages
        SET is_read = 1
        WHERE sender_username = ? AND recipient_username = ? AND is_read = 0
        ''', (other_username, username))
        
        conn.commit()
        return cursor.rowcount
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        conn.rollback()
        return 0
    finally:
        conn.close()

def get_recent_conversations(username: str, limit: int = 20) -> List[Dict[str, Any]]:
    """
    Get a list of recent conversations for a user using an optimized query.
    
    Args:
        username: The username to get conversations for
        limit: Maximum number of conversations to return
        
    Returns:
        List of conversation dictionaries with last message and unread count

    Raises:
        sqlite3.Error: If a database error occurs.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # This query uses CTEs to first identify all messages involving the user,
    # then ranks them per conversation partner to find the latest message.
    # It also calculates unread counts from each partner to the current user.
    # Finally, it joins these results to present a list of recent conversations.
    query = """
    WITH UserMessages AS (
        SELECT
            id,
            sender_username,
            recipient_username,
            CASE
                WHEN sender_username = :current_user THEN recipient_username
                ELSE sender_username
            END AS partner_username,
            content,
            timestamp,
            is_read,
            client_message_id, 
            signature,
            ROW_NUMBER() OVER (PARTITION BY
                CASE
                    WHEN sender_username = :current_user THEN recipient_username
                    ELSE sender_username
                END
                ORDER BY timestamp DESC
            ) as rn
        FROM messages
        WHERE sender_username = :current_user OR recipient_username = :current_user
    ),
    LastMessageDetails AS (
        SELECT
            id,
            sender_username,
            recipient_username,
            partner_username,
            content,
            timestamp,
            client_message_id, 
            signature
        FROM UserMessages
        WHERE rn = 1
    ),
    UnreadCounts AS (
        SELECT
            sender_username AS partner_username,
            COUNT(*) AS unread_count
        FROM messages
        WHERE recipient_username = :current_user AND is_read = 0
        GROUP BY sender_username
    )
    SELECT
        lmd.partner_username AS partner,
        lmd.id AS last_message_id,
        lmd.sender_username AS last_message_sender,
        lmd.recipient_username AS last_message_recipient,
        lmd.content AS last_message_content,
        lmd.timestamp AS last_message_timestamp,
        lmd.client_message_id AS last_message_client_id,
        lmd.signature AS last_message_signature,
        COALESCE(uc.unread_count, 0) AS unread_count
    FROM LastMessageDetails lmd
    LEFT JOIN UnreadCounts uc ON lmd.partner_username = uc.partner_username
    ORDER BY lmd.timestamp DESC
    LIMIT :limit_val;
    """
    
    conversations_result = []
    try:
        cursor.execute(query, {"current_user": username, "limit_val": limit})
        rows = cursor.fetchall()
        
        for row in rows:
            row_dict = dict(row) 
            conversations_result.append({
                'partner': row_dict['partner'],
                'last_message': {
                    'id': row_dict['last_message_id'],
                    'sender_username': row_dict['last_message_sender'],
                    'recipient_username': row_dict['last_message_recipient'],
                    'content': row_dict['last_message_content'],
                    'timestamp': row_dict['last_message_timestamp'],
                    'client_message_id': row_dict['last_message_client_id'],
                    'signature': row_dict['last_message_signature'],
                    # 'is_read' for the last message itself could be added if needed from LastMessageDetails
                },
                'unread_count': row_dict['unread_count'],
                'timestamp': row_dict['last_message_timestamp'] # For client-side sorting if SQL order is not preserved
            })
        return conversations_result
    except sqlite3.Error as e:
        # Re-raise the exception for the caller to handle and log with more context
        raise e 
    finally:
        if conn:
            conn.close()

def mark_message_as_read(message_id: str) -> bool:
    """
    Mark a specific message as read by its ID
    
    Args:
        message_id: The ID of the message to mark as read
        
    Returns:
        Boolean indicating success
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Update the message
        cursor.execute(
            'UPDATE messages SET is_read = 1 WHERE id = ?',
            (message_id,)
        )
        
        # Check if a row was affected
        affected_rows = cursor.rowcount
        conn.commit()
        conn.close()
        
        return affected_rows > 0
    except Exception as e:
        print(f"Error marking message as read: {e}")
        return False

# Initialize the database when this module is imported
init_db()
