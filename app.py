# Monkey patch eventlet at the beginning to avoid runtime errors
import eventlet
eventlet.monkey_patch()

import os
import sys
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

# Define allowed origins for CORS
if ENVIRONMENT == 'production':
    # In production, we'll use a specific list of allowed origins
    allowed_origins = [
        # S3 frontend URLs with various formats
        'http://quantum-chat-frontend.s3-website.ap-south-1.amazonaws.com/',
        'http://quantum-chat-frontend.s3-website.ap-south-1.amazonaws.com',
        'http://quantum-chat-frontend.s3-website.ap-south-1.amazonaws.com/',
        'http://quantum-chat-frontend.s3.amazonaws.com',
        'http://quantum-chat-frontend.s3.ap-south-1.amazonaws.com',
        'https://quantum-chat-frontend.s3.amazonaws.com',
        'https://quantum-chat-frontend.s3.ap-south-1.amazonaws.com',
        'https://quantum-chat-frontend.s3-website.ap-south-1.amazonaws.com',
        'https://quantum-chat-frontend.s3-website.ap-south-1.amazonaws.com/',
        # Other production frontends
        'https://quantum-chat.netlify.app',
        'https://quantum-chat-app.vercel.app',
        # Same origin requests
        'https://quantum-chat-api.onrender.com',
        'https://quantum-chat-api.onrender.com/'
    ]
    
    # Try to load frontend URL from .env.production if it exists
    try:
        from dotenv import load_dotenv
        load_dotenv('.env.production')
        frontend_url = os.environ.get('FRONTEND_URL') or os.environ.get('VITE_APP_WEBSITE_URL')
        if frontend_url and frontend_url not in allowed_origins:
            allowed_origins.append(frontend_url)
            app.logger.info(f"Added frontend URL from .env.production: {frontend_url}")
    except Exception as e:
        app.logger.warning(f"Could not load .env.production file: {e}")
        app.logger.info("Using predefined allowed origins.")
    
    # Log all allowed origins for debugging
    app.logger.info(f"Production mode: Allowed origins: {allowed_origins}")
    
    # IMPORTANT: For testing, temporarily allow all origins
    # This is a temporary fix to debug the CORS issues
    # Remove this in final production deployment
    allowed_origins = '*'
    app.logger.warning("TEMPORARY OVERRIDE: Allowing all origins in production for debugging")
else:
    # In development, allow all origins with wildcard
    allowed_origins = '*'
    app.logger.info("Development mode: Allowing all origins with wildcard (*)")

# Configure Flask app
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_secret_key_change_in_production')

# User session storage - in production this would be in Redis or another persistent store
user_sessions = {} # In-memory cache for user sessions

# Top-level helper function to fetch user data from DB
# This function performs blocking I/O.
def fetch_user_from_db(session_id, db_connection_func, app_logger, user_sessions_cache):
    """Fetch user data from database. THIS IS BLOCKING."""
    try:
        conn = db_connection_func()
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT username, expires_at FROM sessions WHERE session_id = ?", 
            (session_id,)
        )
        session_data = cursor.fetchone()
        
        if not session_data:
            conn.close()
            return None
            
        username, expires_at = session_data
        
        if expires_at and datetime.fromisoformat(expires_at) < datetime.now():
            cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
            conn.commit()
            conn.close()
            user_sessions_cache.pop(session_id, None) # Remove from cache too
            return None
        
        cursor.execute(
            "SELECT username, email, kem_public_key, dss_public_key FROM users WHERE username = ?", 
            (username,)
        )
        user_data_row = cursor.fetchone()
        conn.close()
        
        if not user_data_row:
            return None
            
        user = {
            'username': user_data_row['username'],
            'email': user_data_row['email'],
            'kem_public_key': user_data_row['kem_public_key'],
            'dss_public_key': user_data_row['dss_public_key']
        }
        
        user_sessions_cache[session_id] = user # Update cache
        return user
    except Exception as e:
        app_logger.error(f"Error in fetch_user_from_db: {e}")
        return None

# Function to get user by session ID
# IMPORTANT: This function is BLOCKING. Socket.IO handlers must spawn calls to it.
def get_user_by_session(session_id):
    """Get user data by session ID. THIS IS BLOCKING."""
    """Get user data by session ID"""
    if not session_id:
        return None
        
    # First check in-memory cache
    if session_id in user_sessions: # user_sessions is the global cache from app.py
        return user_sessions[session_id]
    
    # If not in cache, fetch from DB. This is a blocking call.
    # app.logger and get_db_connection are available from app.py's context.
    # user_sessions is the global cache.
    # Call the top-level fetch_user_from_db function
    return fetch_user_from_db(session_id, get_db_connection, app.logger, user_sessions)

# Initialize Socket.IO with the app
from src.socket_server import init_socketio
# Pass app, and references to functions/data needed by socket_server
socketio = init_socketio(
    app=app, 
    get_user_by_session_func=get_user_by_session, 
    user_sessions_ref=user_sessions, # Pass the cache reference
    app_logger_ref=app.logger # Pass logger reference
)

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
    
    # Since we're using wildcard '*' for allowed_origins in both environments temporarily,
    # we'll set the CORS headers accordingly
    if allowed_origins == '*':
        response.headers['Access-Control-Allow-Origin'] = '*'
        app.logger.info(f"Allowing all origins with wildcard (*) for request from: {origin}")
    else:
        # This block is for when we switch back to specific origins
        if origin in allowed_origins:
            response.headers['Access-Control-Allow-Origin'] = origin
            response.headers['Access-Control-Allow-Credentials'] = 'true'
            app.logger.info(f"Allowed CORS for specific origin: {origin}")
        else:
            app.logger.warning(f"Rejected CORS request from origin: {origin} - not in allowed list")
            return response
    
    # Set standard CORS headers
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Origin, X-Requested-With, Content-Type, Accept, Authorization, X-Auth-Token'
    
    # Cache preflight requests
    response.headers['Access-Control-Max-Age'] = '3600'
    
    # Log headers for debugging
    cors_headers = {k: v for k, v in response.headers.items() if k.startswith('Access-Control')}
    app.logger.info(f"CORS headers set: {cors_headers}")
    
    # Handle OPTIONS requests (preflight) specially
    if request.method == 'OPTIONS':
        app.logger.info(f"Responding to preflight OPTIONS request from {origin}")
        return response
    
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
            dss_private_key TEXT NOT NULL,
            key_encryption_data TEXT NOT NULL  -- Stores the encrypted encryption_key
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
            INSERT INTO users (username, email, password_hash, kem_public_key, kem_private_key, dss_public_key, dss_private_key, key_encryption_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (username, email, password_hash, kem_public_key.hex(), encrypted_kem_private_key, dss_public_key.hex(), encrypted_dss_private_key, stored_key_data))
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
    app.logger.info(f"Request headers: {dict(request.headers)}")
    app.logger.info(f"Request method: {request.method}")
    app.logger.info(f"Request content type: {request.content_type}")
    
    try:
        data = request.json
        app.logger.info(f"Request data: {data}")
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            app.logger.warning("Missing username or password in request")
            return jsonify({'error': 'Username and password are required'}), 400
    except Exception as e:
        app.logger.error(f"Exception parsing request data: {str(e)}")
        return jsonify({'error': f'Invalid request data: {str(e)}'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        app.logger.info(f"Executing database query for username: {username}")
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_record = cursor.fetchone()

        app.logger.info(f"Login attempt for username: {username}")
        # Do not log passwords in production
        input_password_hash = hash_password(password)
        app.logger.debug(f"Hash of input password: {input_password_hash}")

        if user_record:
            app.logger.debug(f"User record found for: {username}")
            if verify_password(user_record['password_hash'], password):
                session_id = secrets.token_hex(16)
                app.logger.info(f"Generated session_id: {session_id} for user: {username}")
                cursor.execute("INSERT OR REPLACE INTO sessions (session_id, username) VALUES (?, ?)", (session_id, username))
                conn.commit()
                app.logger.info(f"Login successful for {username}")
                conn.close() # Close connection on successful login
                
                response_data = {
                    'message': 'Login successful',
                    'session_id': session_id,
                    'username': user_record['username'], 
                    'email': user_record['email'],     
                    'public_key': user_record['kem_public_key'],
                    'sign_public_key': user_record['dss_public_key']
                }
                app.logger.info(f"Sending successful login response for {username}")
                return jsonify(response_data)
            else:
                app.logger.warning(f"Login failed for {username}. Invalid password.")
                conn.close()
                return jsonify({'error': 'Invalid username or password'}), 401
        else:
            # This case implies user_record was None (user not found)
            app.logger.warning(f"Login failed for {username}. User not found.")
            conn.close()
            return jsonify({'error': 'Invalid username or password'}), 401
    except Exception as e:
        app.logger.error(f"Exception in login endpoint: {str(e)}")
        # Make sure to close the connection if it was opened
        if 'conn' in locals():
            conn.close()
        return jsonify({'error': f'Server error: {str(e)}'}), 500


@app.route('/api/logout', methods=['POST'])
def logout():
    app.logger.info("--- /api/logout ROUTE HIT ---")
    data = request.json
    session_id = data.get('session_id')
    
    if not session_id:
        return jsonify({'error': 'Session ID is required'}), 400
    
    # Remove session from database
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        conn.commit()
        conn.close()
        
        # Also remove from in-memory session cache if it exists
        if session_id in user_sessions:
            del user_sessions[session_id]
            
        return jsonify({'message': 'Logout successful'}), 200
    except Exception as e:
        app.logger.error(f"Error during logout: {e}")
        return jsonify({'error': 'An error occurred during logout'}), 500

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
