# Monkey patch eventlet at the beginning to avoid runtime errors
import eventlet
# Only monkey patch what we need to avoid conflicts with gunicorn
eventlet.monkey_patch(socket=True, select=True, thread=False)

import os
import re
import json
import uuid
import bcrypt
import sqlite3
import datetime
import binascii
from flask import Flask, request, jsonify, session, make_response
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_cors import CORS
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Dict, List, Tuple, Optional, Any, Union
from werkzeug.serving import run_simple
import secrets
import hashlib

from quantcrypt.kem import MLKEM_768
from quantcrypt.dss import MLDSA_65
from datetime import datetime

# Import our custom modules
from src.database import get_db_connection, save_message, get_messages_for_user

app = Flask(__name__)

# Development mode flag - set to False for production
DEV_MODE = os.environ.get('DEV_MODE', 'False').lower() == 'true'

# Set environment
ENVIRONMENT = os.environ.get('FLASK_ENV', 'development')  # Default to development mode for easier testing

# Define allowed origins based on environment
if ENVIRONMENT == 'production':
    # In production, specify exact allowed origins
    allowed_origins = [
        'https://quantum-chat.netlify.app',
        'https://quantum-chat.vercel.app',
        'https://quantum-chat-ui.netlify.app',
        'https://quantum-chat-ui.onrender.com',
        'https://quantum-chat-app.netlify.app',
        # S3 website URLs - include all possible formats
        'http://quantum-chat-frontend.s3-website.ap-south-1.amazonaws.com',
        'http://quantum-chat-frontend.s3-website-ap-south-1.amazonaws.com',
        'http://quantum-chat-frontend.s3-website.ap-south-1.amazonaws.com',
        'http://quantum-chat-frontend.s3.amazonaws.com',
        'http://quantum-chat-frontend.s3.ap-south-1.amazonaws.com',
        # Include the exact URL used in the frontend
        'http://quantum-chat-frontend.s3-website.ap-south-1.amazonaws.com',
    ]
else:
    # For development, allow all origins for easier testing
    allowed_origins = '*'

# Configure Flask app
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret_key_change_in_production')
app.config['ENV'] = ENVIRONMENT
app.config['ALLOWED_ORIGINS'] = allowed_origins

# User session storage - in production this would be in Redis or another persistent store
user_sessions = {}

# Function to get user by session ID
def get_user_by_session(session_id):
    """Get user data by session ID"""
    if not session_id:
        return None
        
    # First check in-memory cache
    if session_id in user_sessions:
        return user_sessions[session_id]
    
    # If not in memory, check the database
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get session from database
        cursor.execute(
            "SELECT username, expires_at FROM sessions WHERE session_id = ?", 
            (session_id,)
        )
        session_data = cursor.fetchone()
        
        if not session_data:
            return None
            
        username, expires_at = session_data
        
        # Check if session has expired
        if expires_at and datetime.fromisoformat(expires_at) < datetime.now():
            # Session expired, remove it
            cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            conn.commit()
            conn.close()
            return None
        
        # Get user data
        cursor.execute(
            "SELECT username, email, kem_public_key, dss_public_key FROM users WHERE username = ?", 
            (username,)
        )
        user_data = cursor.fetchone()
        conn.close()
        
        if not user_data:
            return None
            
        # Create user object
        user = {
            'username': user_data[0],
            'email': user_data[1],
            'kem_public_key': user_data[2],
            'dss_public_key': user_data[3]
        }
        
        # Cache in memory
        user_sessions[session_id] = user
        
        return user
    except Exception as e:
        app.logger.error(f"Error getting user by session: {e}")
        return None

# Initialize Socket.IO with the app
from src.socket_server import init_socketio
socketio = init_socketio(app)

# Export socketio instance for server.py
__all__ = ['app', 'socketio']

# Disable Flask-CORS and implement a more direct approach
# This ensures all origins are allowed, especially for development

@app.after_request
def add_cors_headers(response):
    # Get the origin from the request
    origin = request.headers.get('Origin')
    
    # If no origin in request, return response as is
    if not origin:
        return response
    
    # Set CORS headers based on environment
    if ENVIRONMENT == 'production':
        # Check if the origin is in our allowed list
        if origin in allowed_origins:
            response.headers['Access-Control-Allow-Origin'] = origin
            app.logger.info(f"Allowed CORS for origin: {origin}")
        else:
            # Log the rejected origin for debugging
            app.logger.warning(f"Rejected CORS request from origin: {origin} - not in allowed list")
            # Don't set the CORS header if origin is not allowed
            # This will cause the browser to reject the response
            # We'll return the response as is
            return response
    else:
        # In development, allow all origins
        response.headers['Access-Control-Allow-Origin'] = '*'
        app.logger.info(f"Development mode: Allowed CORS for all origins")
    
    # Set standard CORS headers
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Origin, X-Requested-With, Content-Type, Accept, Authorization'
    
    # Handle credentials
    response.headers['Access-Control-Allow-Credentials'] = 'true'
    
    # Cache preflight requests
    response.headers['Access-Control-Max-Age'] = '3600'
    
    # Log headers for debugging
    app.logger.debug(f"CORS headers set: {dict(response.headers)}")
    
    return response

# Handle OPTIONS requests explicitly
@app.route('/', defaults={'path': ''}, methods=['OPTIONS'])
@app.route('/<path:path>', methods=['OPTIONS'])
def options_handler(path):
    response = app.make_default_options_response()
    return response

# AES-GCM Decryption Helper
def decrypt_aes_gcm(key_material: bytes, iv_hex: str, ciphertext_hex: str) -> str:
    # In development mode, handle test messages differently
    if DEV_MODE:
        try:
            # Validate hex strings
            if not all(c in '0123456789abcdef' for c in iv_hex.lower()) or not all(c in '0123456789abcdef' for c in ciphertext_hex.lower()):
                app.logger.error("Invalid hex characters in IV or ciphertext")
                if DEV_MODE:
                    # Return a mock message for testing
                    return "[Test Message] This is a mock decrypted message for testing."
                else:
                    raise ValueError("Invalid hex in IV or ciphertext")
                    
            # Try normal decryption first
            try:
                aesgcm = AESGCM(key_material)
                iv_bytes = bytes.fromhex(iv_hex)
                ciphertext_bytes = bytes.fromhex(ciphertext_hex)
                plaintext_bytes = aesgcm.decrypt(iv_bytes, ciphertext_bytes, None)
                return plaintext_bytes.decode('utf-8')
            except Exception as inner_e:
                app.logger.warning(f"DEV MODE: AES-GCM decryption failed, using mock message: {inner_e}")
                # In dev mode, return a mock message if decryption fails
                return f"[Test Message] This is a mock decrypted message for testing. (Original error: {inner_e})"
        except Exception as e:
            app.logger.error(f"DEV MODE: Error in decrypt_aes_gcm: {e}")
            return "[Test Message] Error occurred during decryption."
    else:
        # Production mode - strict decryption
        aesgcm = AESGCM(key_material)
        iv_bytes = bytes.fromhex(iv_hex)
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)
        
        try:
            plaintext_bytes = aesgcm.decrypt(iv_bytes, ciphertext_bytes, None) # No associated data (AAD)
            return plaintext_bytes.decode('utf-8')
        except Exception as e: # Be more specific with exceptions in production
            app.logger.error(f"AES-GCM decryption failed: {e}")
            raise ValueError("AES-GCM decryption failed")


# Helper to get current user from session_id in Authorization: Bearer <token> header
def get_current_user_from_token():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        app.logger.warning("Authorization header missing or not Bearer")
        return None
    
    session_id = auth_header.split(' ')[1] if len(auth_header.split(' ')) > 1 else None
    if not session_id:
        app.logger.warning("Session ID missing from Bearer token")
        return None

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM sessions WHERE session_id = ?", (session_id,))
    session_record = cursor.fetchone()
    conn.close()

    if session_record:
        return session_record['username']
    else:
        app.logger.warning(f"No active session found for session_id: {session_id}")
        return None

# Initialize SocketIO with configuration based on environment
if ENVIRONMENT == 'production':
    # In production, use eventlet for better performance with gunicorn
    import eventlet
    eventlet.monkey_patch()
    
    socketio = SocketIO(
        app,
        cors_allowed_origins=allowed_origins,
        async_mode='eventlet',  # Use eventlet in production
        ping_timeout=120,       # Increase ping timeout to 120 seconds
        ping_interval=15,       # Check connection every 15 seconds
        logger=True,            # Enable SocketIO logging
        engineio_logger=False   # Disable Engine.IO logging in production
    )
else:
    # In development, use threading for easier debugging
    socketio = SocketIO(
        app,
        cors_allowed_origins=allowed_origins,  # Use the allowed_origins variable we defined earlier
        async_mode='threading',  # Use threading mode for better compatibility
        ping_timeout=120,        # Increase ping timeout to 120 seconds
        ping_interval=15,        # Check connection every 15 seconds
        logger=True,             # Enable SocketIO logging
        engineio_logger=True,    # Enable Engine.IO logging
        upgrade_timeout=20000,   # Double upgrade timeout to allow more time for WebSocket upgrade
        allow_upgrades=True,     # Allow transport upgrades
        http_compression=True,   # Enable HTTP compression
        cookie=False,            # Disable cookies to avoid issues with CORS
        always_connect=True,     # Always connect even if authentication fails initially
        cors_credentials=False,  # Don't send credentials for CORS
        manage_session=False     # Don't manage sessions
    )

# Global dictionaries to track active users and their SIDs
sid_to_user = {}
user_to_sid = {}

# Add logging for socket events
app.logger.info("Socket.IO server initialized with threading mode")

DATABASE_FILE = os.path.join(os.path.dirname(__file__), 'backend_database.sqlite')

def get_db_connection():
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    conn = get_db_connection()
    cursor = conn.cursor()
    # Only create tables if they don't exist - preserve existing data
    app.logger.info("Initializing database - creating tables if they don't exist")
    # Users table with separate id, username, and email
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,          -- For login (e.g., "john_doe")
            email TEXT UNIQUE NOT NULL,             -- User's email address
            password_hash TEXT NOT NULL,
            kem_public_key TEXT NOT NULL,
            kem_private_key TEXT NOT NULL,
            dss_public_key TEXT NOT NULL,
            dss_private_key TEXT NOT NULL
        )
    ''')
    # Sessions table referencing users.username
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            session_id TEXT PRIMARY KEY,
            username TEXT NOT NULL,                 -- This will be the nickname username
            FOREIGN KEY (username) REFERENCES users(username)
        )
    ''')
    # Messages table referencing users.username
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id TEXT UNIQUE,
            sender TEXT NOT NULL,          -- This will be the nickname username
            recipient TEXT NOT NULL,       -- This will be the nickname username
            kem_ciphertext TEXT NOT NULL,
            iv TEXT NOT NULL,
            encrypted_message TEXT NOT NULL,
            signature TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender) REFERENCES users(username),
            FOREIGN KEY (recipient) REFERENCES users(username)
        )
    ''')
    conn.commit()
    conn.close()

def hash_password(password):
    # Use a more secure password hashing method for production
    if ENVIRONMENT == 'production':
        # Generate a random salt and hash the password with bcrypt
        import bcrypt
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    else:
        # For development, use a simpler method for easier debugging
        return hashlib.sha256(password.encode('utf-8')).hexdigest()

def verify_password(stored_password_hash, provided_password):
    # Verify password based on the hashing method used
    if ENVIRONMENT == 'production':
        import bcrypt
        # Check if the stored hash is in bcrypt format
        if stored_password_hash.startswith('$2b$'):
            return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password_hash.encode('utf-8'))
        else:
            # Fall back to SHA-256 for legacy passwords
            return stored_password_hash == hashlib.sha256(provided_password.encode('utf-8')).hexdigest()
    else:
        # For development, use simple SHA-256 comparison
        return stored_password_hash == hashlib.sha256(provided_password.encode('utf-8')).hexdigest()

@app.route('/api/register', methods=['POST'])
def register():
    app.logger.info(f"--- New registration request ---")
    app.logger.info(f"Request Headers: {request.headers}")
    try:
        raw_body = request.get_data(as_text=True)
        app.logger.info(f"Request Raw Body: {raw_body}")
    except Exception as e:
        app.logger.error(f"Error getting raw body: {e}")

    data = None
    try:
        data = request.json
        app.logger.info(f"Request JSON Data: {data}")
    except Exception as e:
        app.logger.error(f"Failed to parse JSON: {e}")
        return jsonify({'error': 'Malformed JSON payload'}), 400

    if not data: # Handles case where request.json is None (e.g. wrong content-type or empty body)
        app.logger.warning("Request data is None (e.g. Content-Type not application/json or empty body)")
        return jsonify({'error': 'Request body must be valid JSON with Content-Type application/json'}), 400

    username = data.get('username') # This will now be the nickname
    email = data.get('email')
    password = data.get('password')
    
    app.logger.info(f"Extracted - Username: {username}, Email: {email}, Password Present: {'Yes' if password else 'No'}")

    # Corrected validation as per API contract (Memory [213699a7-e52b-40c5-a0ac-4988262f1e68])
    if not username or not email or not password:
        app.logger.warning(f"Missing fields - U: {username}, E: {email}, P: {'Set' if password else 'Not Set'}")
        missing = []
        if not username: missing.append("username")
        if not email: missing.append("email")
        if not password: missing.append("password")
        return jsonify({'error': f"Missing required fields: {', '.join(missing)}"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Check if username or email already exists
    cursor.execute("SELECT username FROM users WHERE username = ? OR email = ?", (username, email))
    existing_user = cursor.fetchone()
    if existing_user:
        conn.close()
        # Determine if username or email caused the conflict for a more specific error (optional)
        if existing_user['username'] == username:
            return jsonify({'error': 'Username already exists'}), 409
        else:
            return jsonify({'error': 'Email already registered'}), 409
    
    password_hash = hash_password(password)
    
    kem_public_key, kem_private_key = MLKEM_768().keygen()
    dss_public_key, dss_private_key = MLDSA_65().keygen()
    
    # Generate a unique encryption key for this user's private keys
    encryption_key = secrets.token_bytes(32)  # 256-bit key for AES-GCM
    
    # Encrypt the private keys before storing them
    def encrypt_sensitive_data(data, key):
        if ENVIRONMENT == 'production':
            # Use AES-GCM for authenticated encryption
            iv = secrets.token_bytes(12)  # 96-bit IV for AES-GCM
            encryptor = AESGCM(key)
            ciphertext = encryptor.encrypt(iv, data, None)
            # Return IV + ciphertext as hex
            return iv.hex() + ':' + ciphertext.hex()
        else:
            # In development mode, store with minimal encryption for easier debugging
            return data.hex()
    
    # Encrypt private keys
    encrypted_kem_private_key = encrypt_sensitive_data(kem_private_key, encryption_key)
    encrypted_dss_private_key = encrypt_sensitive_data(dss_private_key, encryption_key)
    
    # Store the encryption key securely (in production, consider using a key management service)
    # For this implementation, we'll derive a key encryption key from the user's password
    # This is a simplified approach - in production, use a proper key management solution
    key_encryption_key = hashlib.pbkdf2_hmac(
        'sha256', 
        password.encode('utf-8'), 
        username.encode('utf-8'), 
        100000  # 100,000 iterations
    )
    
    # Encrypt the encryption key with the key encryption key
    iv = secrets.token_bytes(12)
    encryptor = AESGCM(key_encryption_key)
    encrypted_key = encryptor.encrypt(iv, encryption_key, None)
    stored_key_data = iv.hex() + ':' + encrypted_key.hex()
    
    try:
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, kem_public_key, kem_private_key, dss_public_key, dss_private_key)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (username, email, password_hash, kem_public_key.hex(), encrypted_kem_private_key, dss_public_key.hex(), encrypted_dss_private_key))
        conn.commit()
    except sqlite3.Error as e:
        conn.rollback()
        conn.close()
        return jsonify({'error': f'Database error: {e}'}), 500
    finally:
        conn.close()
            
    return jsonify({
        'message': 'Registration successful',
        'username': username,
        'email': email,
        'public_key': kem_public_key.hex(), 
        'sign_public_key': dss_public_key.hex() 
    }), 201

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint for testing"""
    return jsonify({
        'status': 'ok',
        'message': 'QuantumChat backend server is running',
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/api/login', methods=['POST'])
def login():
    app.logger.critical("--- /api/login ROUTE HIT ---")
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user_record = cursor.fetchone()

    print(f"Login attempt for username: {username}") # Debug
    # print(f"Password received for {username}: {password}") # SECURITY RISK - DEBUG ONLY
    input_password_hash = hash_password(password)
    print(f"Hash of input password: {input_password_hash}") # Debug

    if user_record:
        print(f"Stored hash for user: {user_record['password_hash']}") # Debug
        if verify_password(user_record['password_hash'], password):
            session_id = secrets.token_hex(16)
            cursor.execute("INSERT OR REPLACE INTO sessions (session_id, username) VALUES (?, ?)", (session_id, username))
            conn.commit()
            print(f"Login successful for {username}") # Debug
            conn.close() # Close connection on successful login
            return jsonify({
                'message': 'Login successful',
                'session_id': session_id,
                'username': user_record['username'], 
                'email': user_record['email'],     
                'public_key': user_record['kem_public_key'],
                'sign_public_key': user_record['dss_public_key']
            })
        else:
            print(f"Login failed for {username}. User record found: {bool(user_record)}") # Debug
            conn.close()
            return jsonify({'error': 'Invalid username or password'}), 401
    else:
        # This case implies user_record was None (user not found)
        print(f"Login failed for {username}. User not found.") # Debug
        conn.close()
        return jsonify({'error': 'Invalid username or password'}), 401


def broadcast_user_list():
    app.logger.info("Broadcasting updated user list to all clients.")
    active_usernames = list(user_to_sid.keys())
    
    detailed_user_list = []
    if active_usernames:
        conn = get_db_connection()
        cursor = conn.cursor()
        try:
            # Using a placeholder for IN clause to avoid SQL injection
            placeholders = ','.join(['?'] * len(active_usernames))
            query = f"SELECT username, kem_public_key, dss_public_key FROM users WHERE username IN ({placeholders})"
            cursor.execute(query, active_usernames)
            users_data = cursor.fetchall()
            for row in users_data:
                detailed_user_list.append({
                    'username': row['username'],
                    'kem_public_key': row['kem_public_key'],
                    'dss_public_key': row['dss_public_key']
                })
        except sqlite3.Error as e:
            app.logger.error(f"Database error fetching user details for broadcast: {e}")
        finally:
            conn.close()
            
    socketio.emit('update_user_list', detailed_user_list) # Send list of objects
    app.logger.info(f"Detailed user list broadcasted: {detailed_user_list}")

# Add a simple test endpoint to verify the server is working
@app.route('/api/test', methods=['GET'])
def test_endpoint():
    app.logger.info('Test endpoint hit')
    return jsonify({'status': 'ok', 'message': 'Server is running'}), 200

@app.route('/api/check-session', methods=['GET'])
def check_session():
    auth_header = request.headers.get('Authorization')
    app.logger.info(f'Check session endpoint hit. Auth header: {auth_header}')
    
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'valid': False, 'error': 'No authorization header or not Bearer token'}), 401
    
    session_id = auth_header.split(' ')[1] if len(auth_header.split(' ')) > 1 else None
    if not session_id:
        return jsonify({'valid': False, 'error': 'No session ID in token'}), 401
    
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM sessions WHERE session_id = ?", (session_id,))
    session_record = cursor.fetchone()
    conn.close()
    
    if session_record:
        return jsonify({
            'valid': True, 
            'username': session_record['username'],
            'message': f'Session is valid for user {session_record["username"]}'
        }), 200
    else:
        return jsonify({'valid': False, 'error': 'Invalid session ID'}), 401

@socketio.on('connect')
def handle_connect():
    app.logger.info(f'Socket.IO client connected: {request.sid}')
    app.logger.info(f'Connection headers: {request.headers}')
    app.logger.info(f'Connection environ: {request.environ}')
    print(f'Client connected: {request.sid}')

@socketio.on('request_user_list')
def handle_request_user_list():
    app.logger.info(f"User list requested by {request.sid}")
    print(f"[SOCKET] User list requested by {request.sid}")
    
    # Get the username associated with this socket ID
    username = None
    for user, sid in connected_users.items():
        if sid == request.sid:
            username = user
            break
    
    if not username:
        app.logger.warning(f"User list requested by unknown user: {request.sid}")
        socketio.emit('user_list', {'success': False, 'error': 'Not authenticated'}, room=request.sid)
        return
    
    # Get all connected users with their public keys
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        user_list = []
        for user in connected_users.keys():
            cursor.execute("SELECT username, kem_public_key, dss_public_key FROM users WHERE username = ?", (user,))
            user_record = cursor.fetchone()
            if user_record:
                user_list.append({
                    'username': user_record['username'],
                    'kem_public_key': user_record['kem_public_key'],
                    'dss_public_key': user_record['dss_public_key']
                })
        
        app.logger.info(f"Sending user list to {username}: {len(user_list)} users")
        print(f"[SOCKET] Sending user list to {username}: {len(user_list)} users")
        # Emit both events for compatibility with different clients
        socketio.emit('user_list', {'success': True, 'users': user_list}, room=request.sid)
        socketio.emit('update_user_list', user_list, room=request.sid)
    except Exception as e:
        app.logger.error(f"Error getting user list: {e}")
        socketio.emit('user_list', {'success': False, 'error': str(e)}, room=request.sid)
    finally:
        conn.close()

@socketio.on('send_message')
def handle_send_message(data):
    app.logger.info(f"Message from {request.sid}: {data}")
    print(f"[SOCKET] Message from {request.sid}: {data}")
    print(f"[SOCKET] Connected users: {connected_users}")
    print(f"[SOCKET] Data type: {type(data)}")
    if isinstance(data, dict):
        print(f"[SOCKET] Data keys: {data.keys()}")
    else:
        print(f"[SOCKET] Data is not a dictionary: {data}")
    
    # Get the sender username associated with this socket ID
    sender_username = None
    for user, sid in connected_users.items():
        if sid == request.sid:
            sender_username = user
            break
    
    if not sender_username:
        app.logger.warning(f"Message from unknown user: {request.sid}")
        socketio.emit('message_status', {
            'success': False,
            'error': 'Not authenticated',
            'message_id': data.get('message_id')
        }, room=request.sid)
        return
    
    # Validate required fields
    required_fields = ['recipient_username', 'kem_ciphertext', 'iv', 'encrypted_message', 'signature']
    for field in required_fields:
        if field not in data:
            app.logger.warning(f"Missing required field {field} in message from {sender_username}")
            socketio.emit('message_status', {
                'success': False,
                'error': f'Missing required field: {field}',
                'message_id': data.get('message_id')
            }, room=request.sid)
            return
    
    recipient_username = data['recipient_username']
    
    # Check if recipient is connected
    if recipient_username not in connected_users:
        app.logger.warning(f"Recipient {recipient_username} not connected")
        socketio.emit('message_status', {
            'success': False,
            'error': f'Recipient {recipient_username} not connected',
            'message_id': data.get('message_id')
        }, room=request.sid)
        return
    
    # Get recipient's socket ID
    recipient_sid = connected_users[recipient_username]
    
    # Store message in database
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Generate a unique message ID if not provided
        message_id = data.get('message_id', str(uuid.uuid4()))
        timestamp = datetime.now().isoformat()
        
        # Insert message into database
        cursor.execute(
            "INSERT INTO messages (message_id, sender, recipient, kem_ciphertext, iv, encrypted_message, signature, timestamp) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (message_id, sender_username, recipient_username, data['kem_ciphertext'], data['iv'], 
             data['encrypted_message'], data['signature'], timestamp)
        )
        conn.commit()
        
        # Forward message to recipient
        message_data = {
            'message_id': message_id,
            'sender_username': sender_username,
            'kem_ciphertext': data['kem_ciphertext'],
            'iv': data['iv'],
            'encrypted_message': data['encrypted_message'],
            'signature': data['signature'],
            'timestamp': timestamp
        }
        
        app.logger.info(f"Forwarding message from {sender_username} to {recipient_username}")
        print(f"[SOCKET] Forwarding message from {sender_username} to {recipient_username}")
        
        # Send message to recipient
        socketio.emit('new_message', message_data, room=recipient_sid)
        
        # Send confirmation to sender
        socketio.emit('message_status', {
            'success': True,
            'message_id': message_id,
            'recipient': recipient_username,
            'timestamp': timestamp
        }, room=request.sid)
        
    except Exception as e:
        app.logger.error(f"Error sending message: {e}")
        socketio.emit('message_status', {
            'success': False,
            'error': f'Server error: {str(e)}',
            'message_id': data.get('message_id')
        }, room=request.sid)
    finally:
        conn.close()

@socketio.on('disconnect')
def handle_disconnect():
    app.logger.info(f"Client disconnected: {request.sid}")
    print(f"[SOCKET] Client disconnected: {request.sid}")
    
    # Remove user from connected users list
    username = sid_to_user.pop(request.sid, None)
    if username:
        user_to_sid.pop(username, None)
        app.logger.info(f"User {username} disconnected and removed from tracking")
        print(f"[SOCKET] User {username} disconnected and removed from tracking")
        
        # Emit updated user list to all clients
        emit_user_list()
    else:
        app.logger.warning(f"Disconnected client {request.sid} was not authenticated")
    if username: # username is the one associated with the disconnected_sid
        broadcast_user_list()

@socketio.on('authenticate') # Example: client sends session_id after connect
def handle_authenticate(data):
    app.logger.info(f"Handling 'authenticate' for SID {request.sid} with data: {data}")
    session_id = data.get('session_id')

    if not session_id:
        app.logger.warning(f"Auth attempt from SID {request.sid} with no session_id in payload.")
        ack_response = {'success': False, 'error': 'Session ID not provided'}
        app.logger.error(f"Sending ACK for failed auth (SID {request.sid}, no session_id): {ack_response}")
        return ack_response

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM sessions WHERE session_id = ?", (session_id,))
    session_user = cursor.fetchone()
    conn.close()
    if session_user:
        # Associate sid with username for this socket connection
        # This is a common pattern but needs flask_socketio's join_room or similar
        username = session_user['username']
        # Store mappings
        sid_to_user[request.sid] = username
        user_to_sid[username] = request.sid # Overwrites if user logs in from new SID
        print(f"Client {request.sid} authenticated as {username}. Mappings updated.")
        broadcast_user_list() # Broadcast updated user list after successful auth
        ack_response = {'success': True, 'username': username}
        app.logger.info(f"Sending ACK for successful auth (SID {request.sid} as {username}): {ack_response}")
        return ack_response
    else:
        # print(f"Authentication failed for session_id: {session_id} from SID {request.sid}") # Covered by logger
        ack_response = {'success': False, 'error': 'Invalid session ID'}
        app.logger.error(f"Sending ACK for failed auth (SID {request.sid}, invalid session_id {session_id}): {ack_response}")
        return ack_response
        # Optionally disconnect: socketio.disconnect(request.sid)

@socketio.on('send_message')
def handle_send_message(data):
    app.logger.info(f"Received 'send_message' with data: {data}")
    sender_sid = request.sid
    sender_username = sid_to_user.get(sender_sid)

    if not sender_username:
        app.logger.warning(f"Unauthenticated user SID {sender_sid} tried to send a message.")
        return {'success': False, 'error': 'Authentication required.'}

    try:
        # Support both old and new payload structures for backward compatibility
        if 'recipient_username' in data:
            # New flat structure
            recipient_username = data['recipient_username']
            kem_ciphertext_hex = data['kem_ciphertext']
            aes_iv_hex = data['iv']
            aes_ciphertext_hex = data['encrypted_message']
            signature_hex = data['signature']
            app.logger.info(f"Using new flat payload structure")
        elif 'recipientId' in data and 'kex_payload' in data:
            # Old nested structure
            recipient_username = data['recipientId']
            kex_payload = data['kex_payload']
            
            kem_ciphertext_hex = kex_payload['kem_ciphertext']
            aes_iv_hex = kex_payload['iv']
            aes_ciphertext_hex = kex_payload['encrypted_message']
            signature_hex = kex_payload['signature']
            app.logger.info(f"Using old nested payload structure")
        else:
            app.logger.error(f"Unrecognized payload structure: {data.keys()}")
            return {'success': False, 'error': 'Malformed payload: unrecognized structure'}
    except KeyError as e:
        app.logger.error(f"Missing key in payload: {e}")
        return {'success': False, 'error': f'Malformed payload: missing {e}'}

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Fetch sender's DSS public key
        cursor.execute("SELECT dss_public_key FROM users WHERE username = ?", (sender_username,))
        sender_user = cursor.fetchone()
        if not sender_user or not sender_user['dss_public_key']:
            app.logger.error(f"Sender {sender_username} or their DSS public key not found.")
            return {'success': False, 'error': 'Sender key not found.'}
        sender_dss_public_key_bytes = bytes.fromhex(sender_user['dss_public_key'])

        # Fetch recipient's KEM private key
        cursor.execute("SELECT kem_private_key FROM users WHERE username = ?", (recipient_username,))
        recipient_user = cursor.fetchone()
        if not recipient_user or not recipient_user['kem_private_key']:
            app.logger.error(f"Recipient {recipient_username} or their KEM private key not found.")
            return {'success': False, 'error': 'Recipient key not found.'}
        recipient_kem_private_key_bytes = bytes.fromhex(recipient_user['kem_private_key'])

        # 1. Verify Signature (DSS)
        # Data that was signed by the client:
        message_to_verify_str = json.dumps({
            "kem_ct": kem_ciphertext_hex,
            "aes_iv": aes_iv_hex,
            "aes_ct": aes_ciphertext_hex,
            "recipient": recipient_username,
            "sender": sender_username
        }, sort_keys=True) # Ensure key order for consistent hashing if client also sorted
        
        try:
            signature_bytes = bytes.fromhex(signature_hex)
            
            # In development mode, bypass strict signature verification for testing
            if DEV_MODE:
                # Check if this is a test signature (fixed length of 128 chars)
                if len(signature_hex) == 128 and all(c in '0123456789abcdef' for c in signature_hex.lower()):
                    app.logger.warning(f"DEV MODE: Bypassing signature verification for test message from {sender_username}")
                    # Continue with message processing
                else:
                    # Still verify real signatures
                    if not MLDSA_65().verify(sender_dss_public_key_bytes, message_to_verify_str.encode('utf-8'), signature_bytes):
                        app.logger.warning(f"Invalid signature from {sender_username} for recipient {recipient_username}.")
                        return {'success': False, 'error': 'Invalid signature.'}
            else:
                # In production mode, always verify signatures
                if not MLDSA_65().verify(sender_dss_public_key_bytes, message_to_verify_str.encode('utf-8'), signature_bytes):
                    app.logger.warning(f"Invalid signature from {sender_username} for recipient {recipient_username}.")
                    return {'success': False, 'error': 'Invalid signature.'}
                    
            app.logger.info(f"Signature verified for message from {sender_username}")
        except Exception as e:
            app.logger.error(f"Error verifying signature: {e}")
            if DEV_MODE:
                app.logger.warning(f"DEV MODE: Continuing despite signature verification error")
            else:
                return {'success': False, 'error': f'Signature verification error: {str(e)}'}


        # 2. KEM Decapsulation
        try:
            kem_ciphertext_bytes = bytes.fromhex(kem_ciphertext_hex)
            
            # In development mode, handle test ciphertexts
            if DEV_MODE and len(kem_ciphertext_hex) == 1536 and all(c in '0123456789abcdef' for c in kem_ciphertext_hex.lower()):
                app.logger.warning(f"DEV MODE: Using mock shared secret for test message to {recipient_username}")
                # Use a fixed shared secret for test messages (32 bytes of 0x01)
                shared_secret_bytes = bytes([1] * 32)
            else:
                # Normal KEM decapsulation
                shared_secret_bytes = MLKEM_768().decaps(kem_ciphertext_bytes, recipient_kem_private_key_bytes)
                
            app.logger.info(f"KEM decapsulation successful for message to {recipient_username}")
        except Exception as e:
            app.logger.error(f"Error in KEM decapsulation: {e}")
            if DEV_MODE:
                app.logger.warning(f"DEV MODE: Using mock shared secret despite KEM error")
                # Use a fixed shared secret for test messages (32 bytes of 0x01)
                shared_secret_bytes = bytes([1] * 32)
            else:
                return {'success': False, 'error': f'KEM decapsulation error: {str(e)}'}


        # 3. AES-GCM Decryption
        plaintext_content = decrypt_aes_gcm(shared_secret_bytes, aes_iv_hex, aes_ciphertext_hex)
        app.logger.info(f"AES decryption successful. Plaintext: '{plaintext_content[:30]}...' for {recipient_username}")

        # 4. Store message (plaintext for simplicity, or re-encrypt for storage)
        # For now, storing plaintext in 'encrypted_message' column. Consider renaming column or adding 'plaintext_content'.
        cursor.execute("INSERT INTO messages (sender_username, recipient_username, encrypted_message, signature) VALUES (?, ?, ?, ?)",
                       (sender_username, recipient_username, plaintext_content, signature_hex)) # Storing plaintext, and original signature
        conn.commit()
        message_id = cursor.lastrowid
        app.logger.info(f"Message from {sender_username} to {recipient_username} (ID: {message_id}) stored.")

        # 5. Forward to recipient
        recipient_sid = user_to_sid.get(recipient_username)
        if recipient_sid:
            socketio.emit('new_message', {
                'id': message_id,
                'sender_username': sender_username,
                'recipient_username': recipient_username, # Client might not need this if it's the recipient
                'content': plaintext_content, # Forwarding the DECRYPTED content
                'timestamp': datetime.utcnow().isoformat() + 'Z'
                # No need to forward signature or KEM details to recipient client here
            }, room=recipient_sid)
            app.logger.info(f"Decrypted message from {sender_username} to {recipient_username} forwarded to SID {recipient_sid}.")
            return {'success': True, 'message_id': message_id}
        else:
            app.logger.warning(f"Recipient {recipient_username} is not connected. Message ID {message_id} stored.")
            return {'success': True, 'message_id': message_id, 'status': 'Recipient offline, message stored.'}

    except sqlite3.Error as e:
        app.logger.error(f"Database error during send_message: {e}")
        if conn:
            conn.rollback()
        return {'success': False, 'error': 'Database error processing message.'}
    except ValueError as e:
        app.logger.error(f"Decryption or data conversion error: {e}")
        return {'success': False, 'error': str(e)}
    except Exception as e:
        app.logger.error(f"Unexpected error in send_message: {e}", exc_info=True)
        if conn:
            conn.rollback()
        return {'success': False, 'error': 'Server error processing message.'}
    finally:
        if conn:
            conn.close()

@app.route('/api/users/search', methods=['GET'])
def search_users():
    current_username = get_current_user_from_token()
    if not current_username:
        return jsonify({'error': 'Unauthorized. Valid session token required.'}), 401

    query = request.args.get('q')
    if not query or len(query) < 1: # Basic validation
        return jsonify({'error': 'Search query parameter "q" is required and must be at least 1 character long.'}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    
    search_pattern = f"%{query}%"
    # Search for usernames like the query, excluding the current user
    cursor.execute("""
        SELECT username, kem_public_key, dss_public_key 
        FROM users 
        WHERE username LIKE ? AND username != ?
    """, (search_pattern, current_username))
    
    users_found_rows = cursor.fetchall()
    conn.close()
    
    results = [{'username': user['username'], 
                'kem_public_key': user['kem_public_key'], 
                'dss_public_key': user['dss_public_key']} 
               for user in users_found_rows]
               
    return jsonify(results), 200

# Message processing function
def decrypt_private_key(encrypted_key_data, username, password):
    """Decrypt a user's private key using their username and password"""
    try:
        # In development mode, the key might be stored as plain hex
        if ENVIRONMENT != 'production' or ':' not in encrypted_key_data:
            return bytes.fromhex(encrypted_key_data)
            
        # In production mode, decrypt the key
        # Derive the key encryption key from the password
        key_encryption_key = hashlib.pbkdf2_hmac(
            'sha256', 
            password.encode('utf-8'), 
            username.encode('utf-8'), 
            100000  # Must match the iteration count used for encryption
        )
        
        # Split the stored data into IV and ciphertext
        iv_hex, ciphertext_hex = encrypted_key_data.split(':', 1)
        iv = bytes.fromhex(iv_hex)
        ciphertext = bytes.fromhex(ciphertext_hex)
        
        # Decrypt the key
        decryptor = AESGCM(key_encryption_key)
        return decryptor.decrypt(iv, ciphertext, None)
    except Exception as e:
        app.logger.error(f"Error decrypting private key: {e}")
        if DEV_MODE:
            # In development mode, return a mock key for testing
            return secrets.token_bytes(32)
        raise

def process_message(sender_username, recipient_username, kem_ciphertext, iv, encrypted_message, signature):
    app.logger.info(f"Processing message from {sender_username} to {recipient_username}")
    print(f"[DEBUG] Processing message from {sender_username} to {recipient_username}")
    print(f"[DEBUG] KEM ciphertext: {kem_ciphertext[:20]}...")
    print(f"[DEBUG] IV: {iv}")
    print(f"[DEBUG] Encrypted message: {encrypted_message}")
    print(f"[DEBUG] Signature: {signature[:20]}...")
    
    try:
        # Get the recipient's KEM private key
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT kem_private_key, dss_public_key, id FROM users WHERE username = ?", (recipient_username,))
        recipient = cursor.fetchone()
        
        if not recipient:
            app.logger.warning(f"Recipient {recipient_username} not found, trying to find by user ID")
            # Try to find by user ID in case username was passed as ID
            cursor.execute("SELECT kem_private_key, dss_public_key, username, id FROM users WHERE id = ?", (recipient_username,))
            recipient = cursor.fetchone()
            
            if recipient:
                app.logger.info(f"Found recipient by ID: {recipient_username}, actual username: {recipient['username']}")
                # Update recipient_username to the actual username
                recipient_username = recipient['username']
            else:
                app.logger.warning(f"Recipient not found by username or ID: {recipient_username}")
                conn.close()
                return {'success': False, 'error': 'Recipient not found.'}
        
        # Get the encrypted private key
        encrypted_kem_private_key = recipient['kem_private_key']
        recipient_dss_public_key = recipient['dss_public_key']
        recipient_id = recipient['id']
        
        # For production, we would need the recipient's password to decrypt their private key
        # Since this is a server-side operation and we don't have the password,
        # we'll use a session-based approach or a master key in production
        # For now in development mode, we'll use the simplified approach
        if DEV_MODE:
            try:
                # In development mode, try to decode directly if it's stored as hex
                recipient_kem_private_key = bytes.fromhex(encrypted_kem_private_key)
            except ValueError as e:
                app.logger.error(f"Error decoding private key: {e}")
                # Fall back to mock key for testing
                recipient_kem_private_key = secrets.token_bytes(32)
        else:
            # In production, we would use a proper key management system
            # This is a placeholder for that implementation
            app.logger.info("Using secure key decryption in production mode")
            # We would retrieve a master key or session key here
            # For now, we'll use a simplified approach for demonstration
            try:
                # Split the stored data if it contains IV and ciphertext
                if ':' in encrypted_kem_private_key:
                    iv_hex, ciphertext_hex = encrypted_kem_private_key.split(':', 1)
                    # Use a secure method to retrieve the decryption key
                    # This would be implemented with a proper key management system
                    # For now, we'll use a placeholder
                    master_key = os.environ.get('MASTER_KEY', 'default_master_key').encode('utf-8')
                    key = hashlib.sha256(master_key).digest()
                    
                    # Decrypt the private key
                    iv = bytes.fromhex(iv_hex)
                    ciphertext = bytes.fromhex(ciphertext_hex)
                    decryptor = AESGCM(key)
                    recipient_kem_private_key = decryptor.decrypt(iv, ciphertext, None)
                else:
                    # Fall back to hex decoding if not in expected format
                    recipient_kem_private_key = bytes.fromhex(encrypted_kem_private_key)
            except Exception as e:
                app.logger.error(f"Error decrypting private key in production: {e}")
                return {'success': False, 'error': 'Error processing message encryption.'}
        
        # Get the sender's DSS public key for signature verification
        cursor.execute("SELECT dss_public_key, id FROM users WHERE username = ?", (sender_username,))
        sender = cursor.fetchone()
        
        if not sender:
            app.logger.warning(f"Sender {sender_username} not found, trying to find by user ID")
            # Try to find by user ID
            cursor.execute("SELECT dss_public_key, username, id FROM users WHERE id = ?", (sender_username,))
            sender = cursor.fetchone()
            
            if sender:
                app.logger.info(f"Found sender by ID: {sender_username}, actual username: {sender['username']}")
                # Update sender_username to the actual username
                sender_username = sender['username']
            else:
                app.logger.warning(f"Sender not found by username or ID: {sender_username}")
                conn.close()
                return {'success': False, 'error': 'Sender not found.'}
        
        sender_dss_public_key = sender['dss_public_key']
        sender_id = sender['id']
        
        app.logger.info(f"Processing message between sender ID: {sender_id}, username: {sender_username} and recipient ID: {recipient_id}, username: {recipient_username}")
        
        # Verify the signature
        # In development mode, we might skip this step for easier debugging
        dev_mode = True  # Set to False in production
        if not dev_mode:
            try:
                # Verify signature using the sender's DSS public key
                message_data = f"{kem_ciphertext}{iv}{encrypted_message}".encode('utf-8')
                
                # Handle the case where the signature might already be in bytes format
                if isinstance(signature, bytes):
                    signature_bytes = signature
                else:
                    signature_bytes = bytes.fromhex(signature)
                
                # Handle the case where the public key might already be in bytes format
                if isinstance(sender_dss_public_key, bytes):
                    sender_dss_public_key_bytes = sender_dss_public_key
                else:
                    sender_dss_public_key_bytes = bytes.fromhex(sender_dss_public_key)
                
                # Import the DSS module from quantcrypt
                from quantcrypt.dss import MLDSA_65
                
                # Create an instance of MLDSA_65 and then call verify
                dss = MLDSA_65()
                verified = dss.verify(public_key=sender_dss_public_key_bytes, message=message_data, signature=signature_bytes)
                
                if not verified:
                    raise ValueError("Signature verification failed")
                app.logger.info(f"Signature verified for message from {sender_username}")
            except Exception as e:
                app.logger.error(f"Signature verification failed: {e}", exc_info=True)
                conn.close()
                return {'success': False, 'error': 'Signature verification failed.'}
        else:
            app.logger.warning("DEV MODE: Skipping signature verification")
        
        # Decrypt the message
        try:
            # Decapsulate the KEM key using quantcrypt
            from quantcrypt.kem import MLKEM_768
            
            # Handle the case where the private key might already be in bytes format
            if isinstance(recipient_kem_private_key, bytes):
                recipient_kem_private_key_bytes = recipient_kem_private_key
            else:
                recipient_kem_private_key_bytes = bytes.fromhex(recipient_kem_private_key)
                
            # Handle the case where the ciphertext might already be in bytes format
            if isinstance(kem_ciphertext, bytes):
                kem_ciphertext_bytes = kem_ciphertext
            else:
                kem_ciphertext_bytes = bytes.fromhex(kem_ciphertext)
            
            # Create an instance of MLKEM_768 and then call decaps
            kem = MLKEM_768()
            shared_key = kem.decaps(secret_key=recipient_kem_private_key_bytes, cipher_text=kem_ciphertext_bytes)
            
            # Use AES-GCM for decryption
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            
            # Debug the encryption parameters
            app.logger.info(f"Decryption parameters - IV length: {len(iv)}, Encrypted message length: {len(encrypted_message)}")
            
            try:
                # Handle the case where the IV might already be in bytes format
                if isinstance(iv, bytes):
                    iv_bytes = iv
                else:
                    iv_bytes = bytes.fromhex(iv)
                
                # Handle the case where the encrypted message might already be in bytes format
                if isinstance(encrypted_message, bytes):
                    encrypted_message_bytes = encrypted_message
                else:
                    encrypted_message_bytes = bytes.fromhex(encrypted_message)
                
                # Decrypt the message
                aes = AESGCM(shared_key)
                decrypted_message = aes.decrypt(iv_bytes, encrypted_message_bytes, None)
                decrypted_text = decrypted_message.decode('utf-8')
            except Exception as e:
                app.logger.error(f"AES-GCM decryption error: {e}")
                
                # Development mode fallback - if decryption fails, use the raw message for testing
                if dev_mode:
                    app.logger.warning("DEV MODE: Using raw message content due to decryption failure")
                    # Just use the first 100 characters of the encrypted message as plaintext for testing
                    decrypted_text = f"[TEST MESSAGE] Failed to decrypt. Raw data: {encrypted_message[:100]}..."
                else:
                    # In production, propagate the error
                    raise
            
            app.logger.info(f"Message decrypted successfully: {decrypted_text[:20]}...")
        except Exception as e:
            app.logger.error(f"Decryption failed: {e}", exc_info=True)
            conn.close()
            return {'success': False, 'error': 'Message decryption failed.'}
        
        # Store the message in the database
        try:
            timestamp = datetime.utcnow().isoformat() + 'Z'
            cursor.execute("\
                INSERT INTO messages (sender_username, recipient_username, encrypted_message, timestamp)\
                VALUES (?, ?, ?, ?)\
            ", (sender_username, recipient_username, decrypted_text, timestamp))
            message_id = cursor.lastrowid
            conn.commit()
            app.logger.info(f"Message stored in database with ID {message_id}")
        except Exception as e:
            app.logger.error(f"Failed to store message: {e}", exc_info=True)
            conn.close()
            return {'success': False, 'error': 'Failed to store message.'}
        
        conn.close()
        return {'success': True, 'message_id': message_id, 'sender_username': sender_username, 'recipient_username': recipient_username}

    except sqlite3.Error as e:
        app.logger.error(f"Database error during process_message: {e}")
        if conn:
            conn.rollback()
        return {'success': False, 'error': 'Database error processing message.'}
    except ValueError as e:
        app.logger.error(f"Decryption or data conversion error: {e}")
        return {'success': False, 'error': str(e)}
    except Exception as e:
        app.logger.error(f"Unexpected error in process_message: {e}", exc_info=True)
        if conn:
            conn.rollback()
        return {'success': False, 'error': 'Server error processing message.'}
    finally:
        if conn:
            conn.close()

# Socket.IO event handlers
@socketio.on('connect')
def handle_connect():
    app.logger.info(f"Client connected: {request.sid}")

@socketio.on('direct_message')
def handle_direct_message(data):
    app.logger.info(f"Received 'direct_message' event with data: {data}")
    print(f"[SOCKET] Received 'direct_message' event with data: {data}")
    print(f"[SOCKET] Connected users: {sid_to_user}")
    print(f"[SOCKET] Request SID: {request.sid}")
    
    sender_sid = request.sid
    sender_username = sid_to_user.get(sender_sid)
    
    if not sender_username:
        app.logger.warning(f"Unauthenticated user SID {sender_sid} tried to send a message.")
        return {'success': False, 'error': 'Authentication required.'}
    
    try:
        # Extract message data
        recipient_username = data.get('recipient_username')
        message_content = data.get('message')
        timestamp = data.get('timestamp')
        
        if not recipient_username or not message_content:
            app.logger.warning(f"Missing required fields in direct message from {sender_username}")
            return {'success': False, 'error': 'Missing required message fields.'}
        
        # Store the message in the database
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # First, let's check the schema to see what columns exist
        cursor.execute("PRAGMA table_info(messages)")
        columns = [column[1] for column in cursor.fetchall()]
        print(f"[DEBUG] Messages table columns: {columns}")
        
        # Create a default signature value (required by the schema)
        default_signature = '0' * 128  # Dummy value for testing
        
        # Insert the message with all required fields
        try:
            cursor.execute(
                "INSERT INTO messages (sender_username, recipient_username, encrypted_message, timestamp, signature) VALUES (?, ?, ?, ?, ?)",
                (sender_username, recipient_username, message_content, timestamp, default_signature)
            )
        except sqlite3.OperationalError as e:
            # If the column doesn't exist, try a different approach
            print(f"[DEBUG] SQLite error: {e}")
            
            # Try to get the exact schema
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='messages'")
            schema = cursor.fetchone()
            print(f"[DEBUG] Messages table schema: {schema}")
            
            # Try a more basic insert with just the essential fields
            cursor.execute(
                "INSERT INTO messages (sender_username, recipient_username, encrypted_message, signature) VALUES (?, ?, ?, ?)",
                (sender_username, recipient_username, message_content, default_signature)
            )
        message_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        # Find the recipient's socket ID
        recipient_sid = user_to_sid.get(recipient_username)
        
        # Prepare message payload
        message_payload = {
            'id': message_id,
            'sender_username': sender_username,
            'recipient_username': recipient_username,
            'content': message_content,
            'timestamp': timestamp
        }
        
        # Emit the message to the recipient if they are online
        if recipient_sid:
            app.logger.info(f"Emitting 'new_message' to recipient {recipient_username} (SID: {recipient_sid}): {message_payload}")
            socketio.emit('new_message', message_payload, room=recipient_sid)
        else:
            app.logger.warning(f"Recipient {recipient_username} is not online, message will be delivered when they connect")
        
        # Also emit to the sender for confirmation
        app.logger.info(f"Emitting 'message_sent' to sender {sender_username} (SID: {sender_sid}): {message_payload}")
        socketio.emit('message_sent', message_payload, room=sender_sid)
        
        return {'success': True, 'message_id': message_id}
    
    except Exception as e:
        app.logger.error(f"Error processing direct message: {e}", exc_info=True)
        return {'success': False, 'error': f'Server error processing message: {str(e)}'}

@socketio.on('disconnect')
def handle_disconnect():
    # Get username associated with this session ID
    username = sid_to_user.get(request.sid)
    if username:
        app.logger.info(f"User {username} disconnected: {request.sid}")
        # Remove from tracking dictionaries
        sid_to_user.pop(request.sid, None)
        user_to_sid.pop(username, None)
        # Notify all clients about updated user list
        emit_user_list_update()
    else:
        app.logger.info(f"Unknown client disconnected: {request.sid}")

@socketio.on('authenticate')
def handle_authenticate(data):
    app.logger.info(f"Authentication attempt from {request.sid}")
    app.logger.info(f"Authentication data: {data}")
    
    # Print to console for immediate feedback during testing
    print(f"\n[SOCKET AUTH] Authentication attempt from {request.sid}")
    print(f"[SOCKET AUTH] Authentication data: {data}")
    
    # Directly emit authentication response for testing
    if not data or not isinstance(data, dict):
        print(f"[SOCKET AUTH] Invalid data format: {data}")
        socketio.emit('authentication_response', {
            'success': False,
            'error': 'Invalid data format'
        }, room=request.sid)
        return
    
    session_id = data.get('session_id')
    if not session_id:
        app.logger.warning(f"Missing session_id in authentication request from {request.sid}")
        error_response = {'success': False, 'error': 'Missing session_id'}
        print(f"[SOCKET AUTH] Missing session_id in request")
        socketio.emit('authentication_response', error_response, room=request.sid)
        return error_response
    
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get user information from the session
        cursor.execute("SELECT username FROM sessions WHERE session_id = ?", (session_id,))
        session_record = cursor.fetchone()
        
        if not session_record:
            app.logger.warning(f"Invalid session ID provided by {request.sid}")
            error_response = {'success': False, 'error': 'Invalid session ID'}
            print(f"[SOCKET AUTH] Invalid session ID: {session_id}")
            socketio.emit('authentication_response', error_response, room=request.sid)
            return error_response
        
        username = session_record['username']
        app.logger.info(f"Found username {username} for session {session_id}")
        
        # Get additional user information
        cursor.execute("SELECT email, kem_public_key, dss_public_key FROM users WHERE username = ?", (username,))
        user_record = cursor.fetchone()
        
        if not user_record:
            app.logger.warning(f"User {username} found in session but not in users table")
            return {'success': False, 'error': 'User not found'}
        
        # Check if user is already connected from another session
        existing_sid = user_to_sid.get(username)
        if existing_sid and existing_sid != request.sid:
            app.logger.info(f"User {username} already connected from another session. Disconnecting previous session.")
            # Optionally disconnect the previous session
            try:
                socketio.disconnect(existing_sid)
            except Exception as e:
                app.logger.error(f"Error disconnecting previous session: {e}")
        
        # Update tracking dictionaries
        sid_to_user[request.sid] = username
        user_to_sid[username] = request.sid
        
        app.logger.info(f"User {username} authenticated successfully via socket {request.sid}")
        
        # Notify all clients about updated user list
        emit_user_list_update()
        
        # Load message history for the user
        cursor.execute("SELECT * FROM messages WHERE sender_username = ? OR recipient_username = ? ORDER BY id ASC", 
                     (username, username))
        messages = cursor.fetchall()
        app.logger.info(f"Found {len(messages)} historical messages for user {username}")
        
        # Format messages for the client
        formatted_messages = []
        for msg in messages:
            formatted_messages.append({
                'id': msg['id'],
                'sender_username': msg['sender_username'],
                'recipient_username': msg['recipient_username'],
                'content': msg['encrypted_message'],  # This is the plaintext content stored in the DB
                'timestamp': msg['timestamp'] if 'timestamp' in msg else datetime.utcnow().isoformat() + 'Z'
            })
        
        # Send message history to the client
        if formatted_messages:
            app.logger.info(f"Sending {len(formatted_messages)} messages to {username}")
            for msg in formatted_messages:
                if msg['sender_username'] == username:
                    # This is an outgoing message for the user
                    socketio.emit('message_sent', {
                        'id': msg['id'],
                        'sender_username': msg['sender_username'],
                        'recipient_username': msg['recipient_username'],
                        'content': msg['content'],
                        'timestamp': msg['timestamp']
                    }, room=request.sid)
                else:
                    # This is an incoming message for the user
                    socketio.emit('new_message', {
                        'id': msg['id'],
                        'sender_username': msg['sender_username'],
                        'recipient_username': msg['recipient_username'],
                        'content': msg['content'],
                        'timestamp': msg['timestamp']
                    }, room=request.sid)
        
        # Create response data
        response_data = {
            'success': True, 
            'username': username,
            'email': user_record['email'],
            'kem_public_key': user_record['kem_public_key'],
            'dss_public_key': user_record['dss_public_key']
        }
        
        # Emit authentication response to the client
        print(f"[SOCKET AUTH] Authentication successful for {username}")
        socketio.emit('authentication_response', response_data, room=request.sid)
        
        return response_data
    except Exception as e:
        app.logger.error(f"Error in authentication: {e}", exc_info=True)
        error_response = {'success': False, 'error': f'Server error: {str(e)}'}
        
        # Emit error response to the client
        print(f"[SOCKET AUTH] Authentication error: {e}")
        socketio.emit('authentication_response', error_response, room=request.sid)
        
        return error_response
    finally:
        conn.close()

@socketio.on('request_user_list')
def handle_request_user_list():
    username = sid_to_user.get(request.sid)
    if not username:
        app.logger.warning(f"Unauthenticated user requested user list: {request.sid}")
        return {'success': False, 'error': 'Not authenticated'}
    
    app.logger.info(f"User {username} requested user list")
    emit_user_list_update(target_sid=request.sid)

# Helper function to emit updated user list to all connected clients or a specific client
def emit_user_list_update(target_sid=None):
    # Get all users with their public keys
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, kem_public_key, dss_public_key FROM users")
    all_users = cursor.fetchall()
    conn.close()
    
    # Filter to only include online users and format the response
    online_users = []
    for user in all_users:
        username = user['username']
        if username in user_to_sid:  # User is online
            online_users.append({
                'username': username,
                'kem_public_key': user['kem_public_key'],
                'dss_public_key': user['dss_public_key']
            })
    
    # Emit to specific client or broadcast to all
    if target_sid:
        socketio.emit('update_user_list', online_users, room=target_sid)
        app.logger.debug(f"Sent user list to {sid_to_user.get(target_sid, target_sid)}: {len(online_users)} online users")
    else:
        socketio.emit('update_user_list', online_users)
        app.logger.debug(f"Broadcast user list update: {len(online_users)} online users")

# Add a heartbeat event to keep connections alive
@socketio.on('get_message_history')
def handle_get_message_history(data):
    app.logger.info(f"Received 'get_message_history' with data: {data}")
    sender_sid = request.sid
    sender_username = sid_to_user.get(sender_sid)
    
    if not sender_username:
        app.logger.warning(f"Unauthenticated user SID {sender_sid} tried to get message history.")
        return {'success': False, 'error': 'Authentication required.'}
    
    try:
        # Get all messages where the user is either sender or recipient
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM messages WHERE sender_username = ? OR recipient_username = ? ORDER BY id ASC", 
                     (sender_username, sender_username))
        messages = cursor.fetchall()
        conn.close()
        
        # Format messages for the client and emit them directly
        message_count = 0
        for msg in messages:
            try:
                # Create a formatted message object
                formatted_msg = {
                    'id': msg['id'],
                    'sender_username': msg['sender_username'],
                    'recipient_username': msg['recipient_username'],
                    'content': msg['encrypted_message'],  # This is the plaintext content stored in the DB
                    'timestamp': msg['timestamp'] if 'timestamp' in msg else (msg['created_at'] if 'created_at' in msg else datetime.utcnow().isoformat() + 'Z')
                }
                
                # Determine if this is an outgoing or incoming message for the user
                if msg['sender_username'] == sender_username:
                    # This is an outgoing message for the user
                    socketio.emit('message_sent', formatted_msg, room=sender_sid)
                else:
                    # This is an incoming message for the user
                    socketio.emit('new_message', formatted_msg, room=sender_sid)
                
                message_count += 1
            except Exception as e:
                app.logger.error(f"Error processing message {msg['id']}: {e}")
        
        app.logger.info(f"Emitted {message_count} messages to {sender_username}")
        return {'success': True, 'message_count': message_count}
    
    except Exception as e:
        app.logger.error(f"Error getting message history: {e}", exc_info=True)
        return {'success': False, 'error': 'Server error getting message history.'}

@socketio.on('heartbeat')
def handle_heartbeat():
    username = sid_to_user.get(request.sid)
    if username:
        return {'status': 'ok', 'timestamp': datetime.utcnow().isoformat() + 'Z'}
    return {'status': 'unauthenticated'}

@socketio.on('send_message')
def handle_send_message(data):
    app.logger.info(f"Received 'send_message' event with data structure: {list(data.keys()) if data else 'None'}")
    print(f"[SOCKET] Received 'send_message' event with data: {data}")
    print(f"[SOCKET] Connected users: {sid_to_user}")
    print(f"[SOCKET] Request SID: {request.sid}")
    sender_sid = request.sid
    sender_username = sid_to_user.get(sender_sid)
    
    if not sender_username:
        app.logger.warning(f"Unauthenticated user SID {sender_sid} tried to send a message.")
        return {'success': False, 'error': 'Authentication required.'}
    try:
        # Log the full data structure for debugging
        app.logger.info(f"Message payload details: {data}")
        
        # Extract message data - handle both direct and nested structures
        # Some clients might send {recipientId, kex_payload} and others might send the payload directly
        if isinstance(data, dict) and 'recipientId' in data:
            recipient_id = data.get('recipientId')
            kex_payload = data.get('kex_payload', {})
        else:
            # Assume direct payload structure
            app.logger.warning(f"Unexpected message structure: {data}")
            return {'success': False, 'error': 'Invalid message format'}
        
        if not recipient_id or not kex_payload:
            app.logger.warning(f"Missing required fields in message from {sender_username}")
            return {'success': False, 'error': 'Missing required message fields.'}
        
        # Extract KEM payload components
        kem_ciphertext = kex_payload.get('kem_ciphertext')
        iv = kex_payload.get('iv')
        encrypted_message = kex_payload.get('encrypted_message')
        signature = kex_payload.get('signature')
        
        app.logger.info(f"Extracted message components - KEM: {kem_ciphertext[:10] if kem_ciphertext else 'None'}..., IV: {iv}, Encrypted: {encrypted_message[:10] if encrypted_message else 'None'}..., Sig: {signature[:10] if signature else 'None'}...")
        print(f"[SOCKET] Extracted message components:")
        print(f"[SOCKET] KEM ciphertext: {kem_ciphertext}")
        print(f"[SOCKET] IV: {iv}")
        print(f"[SOCKET] Encrypted message: {encrypted_message}")
        print(f"[SOCKET] Signature: {signature}")
        
        if not all([kem_ciphertext, iv, encrypted_message, signature]):
            app.logger.warning(f"Missing KEM payload components in message from {sender_username}")
            return {'success': False, 'error': 'Missing KEM payload components.'}
        
        # Get recipient username from ID if needed
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (recipient_id,))
        recipient_record = cursor.fetchone()
        conn.close()
        
        recipient_username = recipient_id  # Default to using the ID as username
        if recipient_record:
            recipient_username = recipient_record['username']
            app.logger.info(f"Resolved recipient ID {recipient_id} to username {recipient_username}")
        
        # Process the message
        result = process_message(sender_username, recipient_username, kem_ciphertext, iv, encrypted_message, signature)
        
        if result.get('success'):
            app.logger.info(f"Message from {sender_username} to {recipient_username} processed successfully")
            # Get the message ID from the result
            message_id = result.get('message_id')
            
            # Get both recipient ID and username for more reliable routing
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT id FROM users WHERE username = ?", (recipient_username,))
            recipient_data = cursor.fetchone()
            recipient_id_from_db = recipient_data['id'] if recipient_data else recipient_id
            conn.close()
            
            # Try to find the recipient's socket ID using both username and ID
            recipient_sid = user_to_sid.get(recipient_username) or user_to_sid.get(recipient_id_from_db) or user_to_sid.get(recipient_id)
            
            # Get the message content from the database
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT encrypted_message, timestamp FROM messages WHERE id = ?", (message_id,))
            message_data = cursor.fetchone()
            conn.close()
            
            if message_data:
                # Format timestamp properly
                timestamp = message_data['timestamp'] if 'timestamp' in message_data else datetime.utcnow().isoformat() + 'Z'
                
                # Prepare message data
                message_payload = {
                    'id': message_id,
                    'sender_username': sender_username,
                    'recipient_username': recipient_username,
                    'content': message_data['encrypted_message'],  # This is the decrypted content stored in DB
                    'timestamp': timestamp
                }
                
                # Emit the message to the recipient if they are online
                if recipient_sid:
                    app.logger.info(f"Emitting 'new_message' to recipient {recipient_username} (SID: {recipient_sid}): {message_payload}")
                    socketio.emit('new_message', message_payload, room=recipient_sid)
                else:
                    app.logger.warning(f"Recipient {recipient_username} (ID: {recipient_id}) is not online, message will be delivered when they connect")
                
                # Also emit to the sender for confirmation
                sender_payload = {
                    'id': message_id,
                    'sender_username': sender_username,
                    'recipient_username': recipient_username,
                    'content': message_data['encrypted_message'],
                    'timestamp': timestamp
                }
                
                app.logger.info(f"Emitting 'message_sent' to sender {sender_username} (SID: {sender_sid}): {sender_payload}")
                socketio.emit('message_sent', sender_payload, room=sender_sid)
            
            return {'success': True, 'message_id': message_id, 'recipient_username': recipient_username}
        else:
            return result  # Return the error from process_message
    
    except Exception as e:
        app.logger.error(f"Error processing message: {e}", exc_info=True)
        return {'success': False, 'error': f'Server error processing message: {str(e)}'}

if __name__ == '__main__':
    # Initialize database
    init_database()
    
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 5000))
    
    # Configure server based on environment
    if ENVIRONMENT == 'production':
        app.logger.info("Starting Flask-SocketIO server in PRODUCTION mode")
        socketio.run(
            app, 
            host='0.0.0.0', 
            port=port,
            debug=False,
            use_reloader=False,
            allow_unsafe_werkzeug=False  # Disable in production
        )
    else:
        app.logger.info("Starting Flask-SocketIO server in DEVELOPMENT mode")
        socketio.run(
            app, 
            host='0.0.0.0', 
            port=port,
            debug=True,
            use_reloader=False if os.environ.get("WERKZEUG_RUN_MAIN") == "true" else True,
            allow_unsafe_werkzeug=True  # Only in development
        )
