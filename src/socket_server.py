import os
import json
import uuid
import datetime
from typing import Dict, List, Any, Optional, Set
from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
import eventlet # Ensure eventlet is imported
import sqlite3
import secrets
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from quantcrypt.kem import MLKEM_768
from quantcrypt.dss import MLDSA_65
from .database import save_message, get_messages_for_user, mark_messages_as_read, get_db_connection # Ensure get_db_connection is imported

# Development mode flag - set to False for production
DEV_MODE = os.environ.get('DEV_MODE', 'False').lower() == 'true'

# User session tracking
sid_to_user: Dict[str, str] = {}  # Maps socket ID to username
user_to_sid: Dict[str, str] = {}  # Maps username to socket ID
user_rooms: Dict[str, Set[str]] = {}  # Maps username to set of rooms they're in

# AES-GCM Decryption Helper (adapted from app.py)
def decrypt_aes_gcm(key_material: bytes, iv_hex: str, ciphertext_hex: str, app_logger_ref) -> str:
    # In development mode, handle test messages differently
    if DEV_MODE:
        try:
            # Validate hex strings
            if not all(c in '0123456789abcdef' for c in iv_hex.lower()) or not all(c in '0123456789abcdef' for c in ciphertext_hex.lower()):
                app_logger_ref.error("Invalid hex characters in IV or ciphertext")
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
                app_logger_ref.warning(f"DEV MODE: AES-GCM decryption failed, using mock message: {inner_e}")
                # In dev mode, return a mock message if decryption fails
                return f"[Test Message] This is a mock decrypted message for testing. (Original error: {inner_e})"
        except Exception as e:
            app_logger_ref.error(f"DEV MODE: Error in decrypt_aes_gcm: {e}")
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
            app_logger_ref.error(f"AES-GCM decryption failed: {e}")
            raise ValueError("AES-GCM decryption failed")


# Core processing logic for encrypted messages (adapted from app.py's process_message)
# This function is designed to be run asynchronously via eventlet.spawn
def _process_encrypted_message_async(
    socketio_ref, app_logger_ref, get_db_connection_func, save_message_func,
    sid_to_user_ref, user_to_sid_ref,
    sender_username, recipient_username, 
    kem_ciphertext_hex, iv_hex, encrypted_message_hex, signature_hex,
    client_message_id, sender_sid
):
    conn = None
    try:
        app_logger_ref.info(f"_process_encrypted_message_async started for {sender_username} -> {recipient_username}")
        conn = get_db_connection_func()
        cursor = conn.cursor()

        # 1. Get recipient's KEM private key
        cursor.execute("SELECT kem_private_key, id FROM users WHERE username = ?", (recipient_username,))
        recipient_user_data = cursor.fetchone()
        if not recipient_user_data:
            app_logger_ref.error(f"Recipient {recipient_username} not found.")
            socketio_ref.emit('encrypted_message_error', {'client_message_id': client_message_id, 'error': 'Recipient not found.'}, room=sender_sid)
            return
        
        encrypted_kem_private_key_hex = recipient_user_data['kem_private_key']
        # Simplified private key handling for PoC (in production, this needs secure decryption)
        # Assuming it's stored as hex and needs no further decryption for now in socket_server context
        try:
            recipient_kem_private_key_bytes = bytes.fromhex(encrypted_kem_private_key_hex)
        except ValueError:
            app_logger_ref.error(f"Failed to decode recipient KEM private key for {recipient_username}")
            socketio_ref.emit('encrypted_message_error', {'client_message_id': client_message_id, 'error': 'Internal server error processing keys.'}, room=sender_sid)
            return

        # 2. Get sender's DSS public key
        cursor.execute("SELECT dss_public_key FROM users WHERE username = ?", (sender_username,))
        sender_user_data = cursor.fetchone()
        if not sender_user_data:
            app_logger_ref.error(f"Sender {sender_username} not found.")
            socketio_ref.emit('encrypted_message_error', {'client_message_id': client_message_id, 'error': 'Sender not found.'}, room=sender_sid)
            return
        try:
            sender_dss_public_key_bytes = bytes.fromhex(sender_user_data['dss_public_key'])
        except ValueError:
            app_logger_ref.error(f"Failed to decode sender DSS public key for {sender_username}")
            socketio_ref.emit('encrypted_message_error', {'client_message_id': client_message_id, 'error': 'Internal server error processing keys.'}, room=sender_sid)
            return

        # 3. Verify Signature
        if not DEV_MODE:
            try:
                message_data_to_verify = f"{kem_ciphertext_hex}{iv_hex}{encrypted_message_hex}".encode('utf-8')
                signature_bytes = bytes.fromhex(signature_hex)
                dss = MLDSA_65()
                verified = dss.verify(public_key=sender_dss_public_key_bytes, message=message_data_to_verify, signature=signature_bytes)
                if not verified:
                    raise ValueError("Signature verification failed")
                app_logger_ref.info(f"Signature verified for message from {sender_username} to {recipient_username}")
            except Exception as e:
                app_logger_ref.error(f"Signature verification failed for {sender_username}: {e}")
                socketio_ref.emit('encrypted_message_error', {'client_message_id': client_message_id, 'error': 'Signature verification failed.'}, room=sender_sid)
                return
        else:
            app_logger_ref.warning(f"DEV_MODE: Skipping signature verification for {sender_username}")

        # 4. Decapsulate KEM to get shared key
        try:
            kem_ciphertext_bytes = bytes.fromhex(kem_ciphertext_hex)
            kem = MLKEM_768()
            shared_key_bytes = kem.decaps(secret_key=recipient_kem_private_key_bytes, cipher_text=kem_ciphertext_bytes)
        except Exception as e:
            app_logger_ref.error(f"KEM decapsulation failed for {recipient_username}: {e}")
            socketio_ref.emit('encrypted_message_error', {'client_message_id': client_message_id, 'error': 'Message decryption failed (KEM).'}, room=sender_sid)
            return

        # 5. Decrypt message using AES-GCM
        try:
            decrypted_text = decrypt_aes_gcm(shared_key_bytes, iv_hex, encrypted_message_hex, app_logger_ref)
            app_logger_ref.info(f"Message from {sender_username} to {recipient_username} decrypted: {decrypted_text[:30]}...")
        except ValueError as e:
            app_logger_ref.error(f"AES-GCM decryption failed for {recipient_username}: {e}")
            socketio_ref.emit('encrypted_message_error', {'client_message_id': client_message_id, 'error': 'Message decryption failed (AES).'}, room=sender_sid)
            return

        # 6. Store decrypted message
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        message_to_store = {
            'sender_username': sender_username,
            'recipient_username': recipient_username,
            'content': decrypted_text, # Storing decrypted content
            'timestamp': timestamp,
            'is_encrypted': True, # Add a flag to indicate it was E2EE
            'is_read': False
        }
        try:
            message_id = save_message_func(message_to_store)
            app_logger_ref.info(f"Encrypted message (ID: {message_id}) from {sender_username} to {recipient_username} stored.")
        except Exception as e:
            app_logger_ref.error(f"Failed to store decrypted message for {sender_username}: {e}")
            socketio_ref.emit('encrypted_message_error', {'client_message_id': client_message_id, 'error': 'Failed to store message.'}, room=sender_sid)
            return

        # 7. Send confirmation to sender
        socketio_ref.emit('encrypted_message_processed', {
            'client_message_id': client_message_id,
            'server_message_id': message_id,
            'status': 'processed and stored',
            'recipient_username': recipient_username,
            'timestamp': timestamp
        }, room=sender_sid)

        # 8. Deliver decrypted message to recipient if online
        if recipient_username in user_to_sid_ref:
            recipient_sid = user_to_sid_ref[recipient_username]
            full_message_to_recipient = {
                'id': message_id,
                'sender_username': sender_username,
                'recipient_username': recipient_username,
                'content': decrypted_text,
                'timestamp': timestamp,
                'is_encrypted': True,
                'is_read': False
            }
            socketio_ref.emit('new_encrypted_message', full_message_to_recipient, room=recipient_sid)
            app_logger_ref.info(f"Delivered decrypted message {message_id} to {recipient_username} (SID: {recipient_sid})")
        else:
            app_logger_ref.info(f"Recipient {recipient_username} is offline. Message {message_id} stored.")

    except sqlite3.Error as e:
        app_logger_ref.error(f"Database error in _process_encrypted_message_async: {e}")
        socketio_ref.emit('encrypted_message_error', {'client_message_id': client_message_id, 'error': 'Database error.'}, room=sender_sid)
    except Exception as e:
        app_logger_ref.error(f"Unexpected error in _process_encrypted_message_async: {e}", exc_info=True)
        socketio_ref.emit('encrypted_message_error', {'client_message_id': client_message_id, 'error': 'Internal server error.'}, room=sender_sid)
    finally:
        if conn:
            conn.close()


def init_socketio(app: Flask, get_user_by_session_func, user_sessions_ref, app_logger_ref) -> SocketIO:
    """Initialize and configure the Socket.IO server"""
    environment = os.environ.get('FLASK_ENV', 'development')
    
    # Logic for allowed_origins (keeping existing logic for now, but using app_logger_ref)
    import sys
    main_module = sys.modules.get('__main__') # Use .get for safety
    
    allowed_origins_val = '*' # Default
    if main_module and hasattr(main_module, 'allowed_origins'):
        allowed_origins_val = main_module.allowed_origins
        app_logger_ref.info(f"Using allowed_origins from main module: {allowed_origins_val}")
    else:
        # Fallback to development mode (allow all origins) or if not found
        app_logger_ref.warning("Could not find allowed_origins in main module or __main__ not found, defaulting to '*' for Socket.IO")

    # Define Socket.IO ping parameters with default values
    sio_ping_timeout = 20  # Default for python-engineio pingTimeout
    sio_ping_interval = 25 # Default for python-engineio pingInterval

    # Optional: Allow overriding from app.config if needed in the future
    # if app and hasattr(app, 'config'):
    #     sio_ping_timeout = app.config.get('SOCKETIO_PING_TIMEOUT', sio_ping_timeout)
    #     sio_ping_interval = app.config.get('SOCKETIO_PING_INTERVAL', sio_ping_interval)

    socketio_instance = SocketIO(
        app,
        async_mode='eventlet',
        cors_allowed_origins=allowed_origins_val,
        ping_timeout=sio_ping_timeout,      # Pass defined value
        ping_interval=sio_ping_interval,    # Pass defined value
        cookie=False,
        cors_credentials=True
    )
    
    app_logger_ref.info(f"Socket.IO CORS configuration: Allowed origins: {allowed_origins_val}, Credentials: True, Cookie: False")
    # Use the defined variables for logging
    app_logger_ref.info(f"Socket.IO initialized: Async mode: {socketio_instance.async_mode}, Ping: {sio_ping_timeout}s/{sio_ping_interval}s, Env: {environment}")
    
    # Pass the necessary functions and references to the top-level event handlers function
    register_event_handlers(socketio_instance, get_user_by_session_func, user_sessions_ref, app_logger_ref)
    
    return socketio_instance

# Top-level function to register all event handlers
def register_event_handlers(socketio: SocketIO, get_user_by_session_func, user_sessions_ref, app_logger_ref) -> None:
    """Register all Socket.IO event handlers."""
    app_logger_ref.info("Registering Socket.IO event handlers...")

    @socketio.on('connect')
    def handle_connect(auth=None):
        app_logger_ref.info(f"!!! Connection attempt received from SID: {request.sid} with auth: {auth}") # ADD THIS LINE
        app_logger_ref.info(f"Client connected: {request.sid}")
        emit('connection_established', {'sid': request.sid, 'status': 'connected'}, room=request.sid)
        # Send the current user list to the newly connected client
        update_user_list(socketio, app_logger_ref, target_sid=request.sid)

    @socketio.on('disconnect')
    def handle_disconnect():
        app_logger_ref.info(f"Client disconnecting: {request.sid}")
        if request.sid in sid_to_user:
            username = sid_to_user[request.sid]
            app_logger_ref.info(f"User {username} (SID: {request.sid}) disconnected.")
            
            # Remove user from primary tracking
            if username in user_to_sid and user_to_sid[username] == request.sid:
                del user_to_sid[username]
            del sid_to_user[request.sid]
            
            # Clean up user-specific rooms
            if username in user_rooms:
                for room_name in list(user_rooms[username]): # Iterate over a copy
                    leave_room(room_name) # SocketIO's leave_room
                    app_logger_ref.info(f"User {username} left Socket.IO room {room_name}")
                del user_rooms[username]

            emit('user_offline', {'username': username}, broadcast=True)
            update_user_list(socketio, app_logger_ref) # Pass app_logger_ref
        else:
            app_logger_ref.info(f"SID {request.sid} disconnected without prior authentication.")

    @socketio.on('authenticate')
    def handle_authentication(data):
        token = data.get('token')
        current_sid = request.sid
        app_logger_ref.info(f"Authentication attempt from SID {current_sid}. Token provided: {'Yes' if token else 'No'}")

        if not token:
            app_logger_ref.warning(f"Auth failed for SID {current_sid}: No token provided.")
            emit('authentication_failed', {'message': 'Authentication token is required.'}, room=current_sid)
            return

        if current_sid in sid_to_user:
            app_logger_ref.info(f"SID {current_sid} already authenticated as {sid_to_user[current_sid]}. Re-sending success.")
            emit('authentication_success', {'username': sid_to_user[current_sid], 'message': 'Already authenticated.'}, room=current_sid)
            return
        
        def _auth_task(): # Asynchronous authentication task
            app_logger_ref.info(f"Starting async auth task for SID: {current_sid}")
            user = get_user_by_session_func(token) # This is expected to be blocking
            
            if user and isinstance(user, dict) and 'username' in user:
                username = user['username']
                app_logger_ref.info(f"Async auth: User {username} identified for SID {current_sid}")
                
                # Handle if user is already connected with a different SID (session takeover)
                if username in user_to_sid and user_to_sid[username] != current_sid:
                    old_sid = user_to_sid[username]
                    app_logger_ref.warning(f"User {username} re-authenticating with new SID {current_sid}. Old SID: {old_sid}. Disconnecting old session.")
                    if old_sid in sid_to_user: del sid_to_user[old_sid] # Clean up old SID mapping
                    # It's important to emit to the specific old_sid before disconnecting it.
                    socketio.emit('force_disconnect', {'reason': 'Session superseded by new login.'}, room=old_sid)
                    socketio.disconnect(sid=old_sid, silent=True) 

                sid_to_user[current_sid] = username
                user_to_sid[username] = current_sid
                
                join_room(username) # Join user-specific room for direct messaging
                if username not in user_rooms: user_rooms[username] = set()
                user_rooms[username].add(username)

                app_logger_ref.info(f"User {username} authenticated successfully with SID {current_sid}. Joined room: {username}")
                socketio.emit('authentication_success', {'username': username, 'message': 'Authentication successful.'}, room=current_sid)
                update_user_list(socketio, app_logger_ref) # Update user list for all clients
            else:
                app_logger_ref.warning(f"Authentication failed for SID {current_sid}: Invalid token or user data from get_user_by_session_func.")
                socketio.emit('authentication_failed', {'message': 'Invalid token or user data.'}, room=current_sid)
        
        eventlet.spawn(_auth_task)

    @socketio.on('send_encrypted_message')
    def handle_send_encrypted_message(data: Dict[str, Any]):
        # Correctly scoped app_logger_ref, sid_to_user, user_to_sid, get_db_connection, save_message, _process_encrypted_message_async are available
        app_logger_ref.info(f"Received 'send_encrypted_message' from SID {request.sid}. ClientMsgID: {data.get('client_message_id', 'N/A')}")
        sender_username = sid_to_user.get(request.sid)

        if not sender_username:
            app_logger_ref.warning(f"send_encrypted_message: Sender not identified for SID {request.sid}. Authentication error.")
            emit('encrypted_message_error', {'client_message_id': data.get('client_message_id'), 'error': 'Authentication required to send encrypted messages.'}, room=request.sid)
            return

        required_fields = ['recipient_username', 'kem_ciphertext_hex', 'iv_hex', 'encrypted_message_hex', 'signature_hex', 'client_message_id']
        missing_fields = [field for field in required_fields if field not in data or not data[field]]
        if missing_fields:
            app_logger_ref.error(f"send_encrypted_message: Missing fields from {sender_username}: {missing_fields}. Data: {data}")
            emit('encrypted_message_error', {'client_message_id': data.get('client_message_id'), 'error': f'Missing required fields: {", ".join(missing_fields)}'}, room=request.sid)
            return
        
        app_logger_ref.info(f"Spawning _process_encrypted_message_async for {sender_username} -> {data['recipient_username']}")
        eventlet.spawn(
            _process_encrypted_message_async, # Global helper function
            socketio, app_logger_ref, get_db_connection, save_message,
            sid_to_user, user_to_sid, # Pass global dicts
            sender_username, data['recipient_username'],
            data['kem_ciphertext_hex'], data['iv_hex'], data['encrypted_message_hex'], data['signature_hex'],
            data['client_message_id'], request.sid
        )

    @socketio.on('direct_message')
    def handle_direct_message(data):
        app_logger_ref.info(f"Received 'direct_message' from SID {request.sid}. To: {data.get('recipient_username')}")
        sender_username = sid_to_user.get(request.sid)
        if not sender_username:
            app_logger_ref.warning(f"direct_message: Sender not identified for SID {request.sid}. Authentication error.")
            emit('error', {'message': 'Authentication required to send messages.'}, room=request.sid)
            return

        recipient_username = data.get('recipient_username')
        message_content = data.get('message')
        client_message_id = data.get('client_message_id', f"dm_{uuid.uuid4().hex}")
        timestamp = data.get('timestamp', datetime.datetime.now(datetime.timezone.utc).isoformat())

        if not recipient_username or not message_content:
            app_logger_ref.error(f"direct_message: Missing recipient or content from {sender_username}. Data: {data}")
            emit('error', {'message': 'Recipient username and message content are required.'}, room=request.sid)
            return
        
        message_to_save = {
            'sender_username': sender_username,
            'recipient_username': recipient_username,
            'content': message_content,
            'timestamp': timestamp,
            'is_encrypted': False,
            'signature': None, 
            'kem_ciphertext': None,
            'iv': None,
            'client_message_id': client_message_id,
            'is_read': False
        }
        
        try:
            saved_message_id = save_message(message_to_save)
            app_logger_ref.info(f"Direct message from {sender_username} to {recipient_username} saved. DB ID: {saved_message_id}")

            emit('message_sent_confirmation', { 
                'db_id': saved_message_id,
                'client_message_id': client_message_id,
                'recipient_username': recipient_username,
                'timestamp': timestamp
            }, room=request.sid)

            recipient_sid = user_to_sid.get(recipient_username)
            if recipient_sid:
                full_message_for_recipient = {**message_to_save, 'id': saved_message_id, 'isOutgoing': False}
                socketio.emit('new_message', full_message_for_recipient, room=recipient_sid) # Send to specific SID
                # Also consider emitting to recipient_username room if they might be connected on multiple devices
                # socketio.emit('new_message', full_message_for_recipient, room=recipient_username)
                app_logger_ref.info(f"Sent direct message {saved_message_id} to online recipient {recipient_username} (SID: {recipient_sid})")
            else:
                app_logger_ref.info(f"Recipient {recipient_username} is offline. Message {saved_message_id} stored for later retrieval.")
        except Exception as e:
            app_logger_ref.error(f"Error saving/sending direct message from {sender_username} to {recipient_username}: {e}", exc_info=True)
            emit('error', {'message': f'Server error processing your direct message: {str(e)}', 'client_message_id': client_message_id}, room=request.sid)

    @socketio.on('get_message_history')
    def handle_get_message_history(data):
        app_logger_ref.info(f"Received 'get_message_history' from SID {request.sid}. Chatting with: {data.get('other_username')}")
        username = sid_to_user.get(request.sid)
        if not username:
            app_logger_ref.warning(f"get_message_history: User not identified for SID {request.sid}. Authentication error.")
            emit('error', {'message': 'Authentication required to fetch history.'}, room=request.sid)
            return

        other_username = data.get('other_username')
        if not other_username:
            app_logger_ref.error(f"get_message_history: 'other_username' not provided by {username}. Data: {data}")
            emit('error', {'message': "'other_username' is required to fetch message history."}, room=request.sid)
            return
        
        # Add pagination parameters here, e.g., data.get('page', 1), data.get('limit', 50)
        try:
            messages_db = get_messages_for_user(username, other_username) # Pass pagination params if used
            messages_to_send = []
            for msg_row in messages_db:
                msg_dict = dict(msg_row) 
                msg_dict['isOutgoing'] = (msg_dict['sender_username'] == username)
                messages_to_send.append(msg_dict)
            
            emit('message_history', {'messages': messages_to_send, 'with_user': other_username}, room=request.sid)
            app_logger_ref.info(f"Sent message history ({len(messages_to_send)} msgs) between {username} and {other_username} to SID {request.sid}")
        except Exception as e:
            app_logger_ref.error(f"Error fetching message history for {username} with {other_username}: {e}", exc_info=True)
            emit('error', {'message': f'Server error fetching message history: {str(e)}'}, room=request.sid)

    @socketio.on('mark_messages_read')
    def handle_mark_messages_read(data):
        app_logger_ref.info(f"Received 'mark_messages_read' from SID {request.sid}. Data: {data}")
        reader_username = sid_to_user.get(request.sid)
        if not reader_username:
            app_logger_ref.warning(f"mark_messages_read: User not identified for SID {request.sid}. Authentication error.")
            emit('error', {'message': 'Authentication required to mark messages as read.'}, room=request.sid)
            return

        # Client should specify whose messages they are marking as read
        sender_username_whose_messages_are_read = data.get('other_username') 
        message_ids_to_mark = data.get('message_ids') # Optional: specific message IDs

        if not sender_username_whose_messages_are_read and not message_ids_to_mark:
            app_logger_ref.error(f"mark_messages_read: Missing 'other_username' (sender of messages) or 'message_ids' from {reader_username}. Data: {data}")
            emit('error', {'message': "Either 'other_username' (sender of the messages) or specific 'message_ids' must be provided."}, room=request.sid)
            return
        
        try:
            # `mark_messages_as_read` in database.py needs to handle these parameters
            # It should mark messages where recipient is `reader_username` and sender is `sender_username_whose_messages_are_read`
            # OR messages specified by `message_ids_to_mark` (owned by `reader_username`)
            count = mark_messages_as_read(reader_username=reader_username, 
                                          sender_username=sender_username_whose_messages_are_read, 
                                          message_ids=message_ids_to_mark)
            
            emit('messages_marked_read_confirmation', 
                 {'count': count, 'marked_for_sender': sender_username_whose_messages_are_read, 'message_ids': message_ids_to_mark}, 
                 room=request.sid)
            app_logger_ref.info(f"{count} messages from {sender_username_whose_messages_are_read} to {reader_username} marked as read.")
            
            # Optionally, notify the other user that their messages were read
            # other_user_sid = user_to_sid.get(sender_username_whose_messages_are_read)
            # if other_user_sid:
            #    socketio.emit('messages_read_by_recipient', 
            #                  {'reader_username': reader_username, 'message_ids': message_ids_to_mark if message_ids_to_mark else 'all_previous'}, 
            #                  room=other_user_sid)

        except Exception as e:
            app_logger_ref.error(f"Error in mark_messages_read for {reader_username} (messages from {sender_username_whose_messages_are_read}): {e}", exc_info=True)
            emit('error', {'message': f'Server error marking messages as read: {str(e)}'}, room=request.sid)

    @socketio.on('request_user_list')
    def handle_request_user_list():
        current_sid = request.sid
        app_logger_ref.info(f"Received 'request_user_list' from SID {current_sid}")
        username = sid_to_user.get(current_sid)
        if not username: # Should be authenticated to request user list
            app_logger_ref.warning(f"request_user_list: Unauthenticated SID {current_sid} attempted to request user list.")
            # Optionally emit an error, or just don't send list if not authenticated
            # emit('error', {'message': 'Authentication required to request user list.'}, room=current_sid)
            return
        update_user_list(socketio, app_logger_ref, target_sid=current_sid) # Pass app_logger_ref and target_sid

    @socketio.on('heartbeat')
    def handle_heartbeat(data=None):
        app_logger_ref.debug(f"Received 'heartbeat' from SID {request.sid}. Data: {data}")
        emit('heartbeat_response', {'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat()}, room=request.sid)
    
    app_logger_ref.info("Socket.IO event handlers registered successfully.")

    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle client disconnection"""
        if request.sid in sid_to_user:
            username = sid_to_user[request.sid]
            print(f"User {username} disconnected")
            
            # Remove user from tracking dictionaries
            del user_to_sid[username]
            del sid_to_user[request.sid]
            
            # Notify other users about this user going offline
            emit('user_offline', {'username': username}, broadcast=True)
            
            # Update the user list for all clients
            update_user_list(socketio)
    
    @socketio.on('authenticate')
    def handle_authentication(data):
        """Handle user authentication using eventlet.spawn for blocking calls."""
        app_logger_ref.info(f"Authentication attempt from socket {request.sid} with data: {data}")

        if request.sid in sid_to_user:
            username = sid_to_user[request.sid]
            app_logger_ref.info(f"Socket {request.sid} already authenticated as {username}")
            emit('authentication_success', {'username': username, 'message': f'Already authenticated as {username}'})
            return

        token = data.get('token')
        if not token:
            app_logger_ref.warning(f"Authentication failed for {request.sid}: No token provided")
            emit('authentication_failed', {'message': 'No token provided'})
            return

        current_sid = request.sid # Capture sid before spawning

        def _perform_auth_async():
            try:
                app_logger_ref.info(f"Async auth started for SID: {current_sid}, Token: {token[:10]}...")
                # get_user_by_session_func is blocking, so it's called inside the spawned greenlet.
                # It uses user_sessions_ref (the cache from app.py) internally.
                user = get_user_by_session_func(token) # This function is passed from app.py

                if user:
                    username = user['username']
                    sid_to_user[current_sid] = username
                    user_to_sid[username] = current_sid
                    app_logger_ref.info(f"User {username} authenticated with SID {current_sid}")
                    socketio.emit('authentication_success', {'username': username, 'message': 'Authentication successful'}, room=current_sid)
                    update_user_list(socketio) # Update user list for all clients
                else:
                    app_logger_ref.warning(f"Authentication failed for SID {current_sid}: Invalid token or user not found for token {token[:10]}...")
                    socketio.emit('authentication_failed', {'message': 'Invalid token or user not found'}, room=current_sid)
            except Exception as e:
                app_logger_ref.error(f"Exception in _perform_auth_async for SID {current_sid}: {e}", exc_info=True)
                socketio.emit('authentication_failed', {'message': 'Server error during authentication.'}, room=current_sid)

        eventlet.spawn(_perform_auth_async)
    
    @socketio.on('direct_message')
    def handle_direct_message(data):
        """Handle direct message between users"""
        # Check if user is authenticated
        if request.sid not in sid_to_user:
            emit('error', {'message': 'Not authenticated'})
            print(f"Socket {request.sid} attempted to send message without authentication")
            return
        
        sender_username = sid_to_user[request.sid]
        recipient_username = data.get('recipient_username')
        message_content = data.get('message')
        client_message_id = data.get('client_message_id')
        timestamp = data.get('timestamp', datetime.datetime.now().isoformat())
        
        print(f"Received direct message from {sender_username} to {recipient_username}")
        print(f"Message data: {data}")
        
        if not recipient_username or not message_content:
            emit('error', {'message': 'Missing recipient or message content'})
            print(f"Missing data in message: recipient={recipient_username}, content_length={len(message_content) if message_content else 0}")
            return
        
        # Create message object
        message_id = f"msg_{uuid.uuid4().hex}"
        message = {
            'id': message_id,
            'sender_username': sender_username,
            'recipient_username': recipient_username,
            'content': message_content,
            'timestamp': timestamp,
            'client_message_id': client_message_id,
            'is_read': False
        }
        
        try:
            # Save message to database
            saved_id = save_message(message)
            print(f"Message saved to database with ID: {saved_id}")
            
            # Send confirmation to sender
            emit('message_sent', {
                'id': saved_id,
                'recipient_username': recipient_username,
                'content': message_content,
                'timestamp': timestamp,
                'client_message_id': client_message_id
            })
            print(f"Sent confirmation to sender {sender_username}")
            
            # Send message to recipient if they're online
            if recipient_username in user_to_sid:
                recipient_sid = user_to_sid[recipient_username]
                print(f"Recipient {recipient_username} is online with SID {recipient_sid}")
                
                # Send to recipient's room
                emit('new_message', message, room=recipient_username)
                print(f"Sent message to {recipient_username} in room {recipient_username}")
                
                # Also try sending directly to their socket ID as a fallback
                emit('new_message', message, to=recipient_sid)
                print(f"Also sent message directly to recipient's socket ID {recipient_sid}")
            else:
                print(f"User {recipient_username} is offline, message saved for later delivery")
                print(f"Current online users: {list(user_to_sid.keys())}")
            
            # Return success response
            emit('direct_message_response', {'success': True, 'message_id': saved_id})
            
        except Exception as e:
            print(f"Error handling direct message: {e}")
            import traceback
            traceback.print_exc()
            emit('direct_message_response', {'success': False, 'error': str(e)})
    
    @socketio.on('mark_as_read')
    def handle_mark_as_read(data):
        """Handle marking messages as read"""
        # Check if user is authenticated
        if request.sid not in sid_to_user:
            emit('error', {'message': 'Not authenticated'})
            return
        
        username = sid_to_user[request.sid]
        message_id = data.get('message_id')
        sender_username = data.get('sender_username')
        
        if not message_id or not sender_username:
            emit('error', {'message': 'Missing message_id or sender_username'})
            return
        
        try:
            # Mark the message as read in the database
            from .database import mark_message_as_read
            success = mark_message_as_read(message_id)
            
            # Notify the sender that their message has been read
            if success and sender_username in user_to_sid:
                sender_sid = user_to_sid[sender_username]
                emit('message_read', {
                    'message_id': message_id,
                    'read_by': username
                }, to=sender_sid)
                
                print(f"Notified {sender_username} that message {message_id} was read by {username}")
            
            # Send confirmation to the client
            emit('mark_as_read_response', {
                'success': success,
                'message_id': message_id
            })
            
        except Exception as e:
            print(f"Error marking message as read: {e}")
            import traceback
            traceback.print_exc()
            emit('mark_as_read_response', {'success': False, 'error': str(e)})
    
    @socketio.on('get_message_history')
    def handle_get_message_history(data):
        """Handle request for message history"""
        # Check if user is authenticated
        if request.sid not in sid_to_user:
            emit('error', {'message': 'Not authenticated'})
            return
        
        username = sid_to_user[request.sid]
        other_username = data.get('other_username')
        
        try:
            # Get messages from database
            if other_username:
                messages = get_messages_for_user(username, other_username)
                # Mark messages from other user as read
                mark_messages_as_read(username, other_username)
            else:
                messages = get_messages_for_user(username)
            
            # Send messages to client
            for message in messages:
                # Convert to dict if it's a sqlite3.Row
                if not isinstance(message, dict):
                    message = dict(message)
                
                # Add isOutgoing flag for client-side rendering
                message['isOutgoing'] = (message['sender_username'] == username)
                
                # Send as individual messages to maintain same event structure
                emit('new_message', message)
            
            # Send confirmation
            emit('message_history_complete', {
                'count': len(messages),
                'username': username,
                'other_username': other_username
            })
            
        except Exception as e:
            print(f"Error getting message history: {e}")
            emit('error', {'message': f'Error getting message history: {str(e)}'})
    
    @socketio.on('get_recent_conversations')
    def handle_get_recent_conversations(data):
        """Handle request for recent conversations asynchronously."""
        current_sid = request.sid
        app_logger_ref.info(f"'get_recent_conversations' event received from SID: {current_sid}. Data: {data}")

        if current_sid not in sid_to_user:
            app_logger_ref.warning(f"SID {current_sid} attempted 'get_recent_conversations' but is not authenticated.")
            emit('error', {'message': 'Not authenticated', 'event': 'get_recent_conversations'}, room=current_sid)
            return
        
        username = sid_to_user[current_sid]
        app_logger_ref.info(f"User {username} (SID: {current_sid}) requesting recent conversations. Spawning async task.")
        
        def _fetch_recent_conversations_async(target_sid, user_name):
            try:
                app_logger_ref.debug(f"Async task: Calling database.get_recent_conversations for user: {user_name}")
                # get_recent_conversations is imported from .database
                # It now re-raises sqlite3.Error on database issues.
                conversations_list = get_recent_conversations(user_name)
                app_logger_ref.info(f"Async task: Successfully retrieved {len(conversations_list) if conversations_list is not None else 'None'} recent conversations for user {user_name}.")
                
                socketio.emit('recent_conversations', {'conversations': conversations_list}, room=target_sid)
            
            except sqlite3.Error as db_err:
                app_logger_ref.error(f"Async task: Database error fetching recent conversations for user {user_name} (SID: {target_sid}): {db_err}", exc_info=True)
                socketio.emit('error', {'message': 'A database error occurred while fetching recent conversations.', 'details': str(db_err), 'event': 'get_recent_conversations'}, room=target_sid)
            except Exception as e:
                app_logger_ref.error(f"Async task: Generic error fetching recent conversations for user {user_name} (SID: {target_sid}): {e}", exc_info=True)
                socketio.emit('error', {'message': 'An unexpected error occurred while fetching recent conversations.', 'details': str(e), 'event': 'get_recent_conversations'}, room=target_sid)

        eventlet.spawn(_fetch_recent_conversations_async, current_sid, username)
    
    @socketio.on('mark_messages_read')
    def handle_mark_messages_read(data):
        """Handle request to mark messages as read"""
        # Check if user is authenticated
        if request.sid not in sid_to_user:
            emit('error', {'message': 'Not authenticated'})
            return
        
        username = sid_to_user[request.sid]
        other_username = data.get('other_username')
        
        if not other_username:
            emit('error', {'message': 'Missing other_username parameter'})
            return
        
        try:
            # Mark messages as read in database
            count = mark_messages_as_read(username, other_username)
            
            # Send confirmation
            emit('messages_marked_read', {
                'count': count,
                'other_username': other_username
            })
            
        except Exception as e:
            print(f"Error marking messages as read: {e}")
            emit('error', {'message': f'Error marking messages as read: {str(e)}'})
    
    @socketio.on('request_user_list')
    def handle_request_user_list():
        """Handle request for user list"""
        update_user_list(socketio, target=request.sid)
    
    @socketio.on('heartbeat')
    def handle_heartbeat():
        """Handle heartbeat to keep connection alive"""
        # Just respond with a pong
        emit('heartbeat_response', {'timestamp': datetime.datetime.now().isoformat()})

    @socketio.on('send_encrypted_message')
    def handle_send_encrypted_message(data):
        app_logger_ref.info(f"Received 'send_encrypted_message' from SID {request.sid} with data keys: {list(data.keys()) if isinstance(data, dict) else 'Non-dict data'}")
        if request.sid not in sid_to_user:
            app_logger_ref.warning(f"Unauthorized 'send_encrypted_message' from SID {request.sid}")
            emit('error', {'message': 'Not authenticated for sending encrypted message'})
            return

        sender_username = sid_to_user[request.sid]
        recipient_username = data.get('recipient_username')
        kem_ciphertext_hex = data.get('kem_ciphertext')
        iv_hex = data.get('iv')
        encrypted_message_hex = data.get('encrypted_message')
        signature_hex = data.get('signature')
        client_message_id = data.get('client_message_id') # For tracking on client side

        if not all([recipient_username, kem_ciphertext_hex, iv_hex, encrypted_message_hex, signature_hex, client_message_id]):
            missing_fields = [field for field, value in {
                'recipient_username': recipient_username, 'kem_ciphertext': kem_ciphertext_hex, 
                'iv': iv_hex, 'encrypted_message': encrypted_message_hex, 
                'signature': signature_hex, 'client_message_id': client_message_id
            }.items() if not value]
            app_logger_ref.error(f"Missing data in 'send_encrypted_message' from {sender_username}. Missing: {missing_fields}")
            emit('encrypted_message_error', {
                'client_message_id': client_message_id,
                'error': 'Missing required data for encrypted message.',
                'missing_fields': missing_fields
            })
            return

        app_logger_ref.info(f"Spawning _process_encrypted_message_async for {sender_username} to {recipient_username}. ClientMsgID: {client_message_id}")
        eventlet.spawn(
            _process_encrypted_message_async,
            socketio, app_logger_ref, get_db_connection, save_message, # Pass direct function references
            sid_to_user, user_to_sid, # Pass global dicts directly
            sender_username, recipient_username,
            kem_ciphertext_hex, iv_hex, encrypted_message_hex, signature_hex,
            client_message_id, request.sid
        )

    # Nested helper function for processing encrypted messages asynchronously
    def _process_encrypted_message_payload(
        current_sid_local: str,
        sender_username_from_auth: str,
        recipient_username_from_payload: str,
        kem_ciphertext_hex: str,
        iv_hex: str,
        encrypted_message_hex: str,
        signature_hex: str,
        client_message_id: Optional[str],
        timestamp_from_client: str
    ):
        conn = None
        try:
            app_logger_ref.info(f"[Thread: {eventlet.getcurrent()}] Processing encrypted message from {sender_username_from_auth} to {recipient_username_from_payload}")
            
            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT kem_private_key, id, username FROM users WHERE username = ?", (recipient_username_from_payload,))
            recipient_db_data = cursor.fetchone()
            if not recipient_db_data:
                cursor.execute("SELECT kem_private_key, id, username FROM users WHERE id = ?", (recipient_username_from_payload,))
                recipient_db_data = cursor.fetchone()

            if not recipient_db_data:
                app_logger_ref.warning(f"Recipient not found: {recipient_username_from_payload}")
                socketio.emit('encrypted_message_failed', {'error': 'Recipient not found.', 'client_message_id': client_message_id}, room=current_sid_local)
                return

            actual_recipient_username = recipient_db_data['username']
            encrypted_kem_private_key_store = recipient_db_data['kem_private_key']
            
            recipient_kem_private_key_bytes: bytes
            if DEV_MODE:
                try:
                    recipient_kem_private_key_bytes = bytes.fromhex(encrypted_kem_private_key_store)
                except ValueError:
                    app_logger_ref.error(f"DEV_MODE: Error decoding recipient KEM PK for {actual_recipient_username}, using mock.")
                    # Generate a valid mock private key for MLKEM_768 if needed for testing
                    _, recipient_kem_private_key_bytes = MLKEM_768().generate_keypair() 
            else:
                try:
                    if ':' in encrypted_kem_private_key_store: # Assuming format IV:Ciphertext for encrypted PK
                        iv_pk_hex, ct_pk_hex = encrypted_kem_private_key_store.split(':', 1)
                        master_key_env = os.environ.get('MASTER_KEY', 'default_master_key_32bytes_!!!!').encode('utf-8')
                        if len(master_key_env) < 32 : master_key_env = master_key_env.ljust(32, b'!') # Pad if too short
                        key_material_master = hashlib.sha256(master_key_env).digest()
                        iv_pk_bytes = bytes.fromhex(iv_pk_hex)
                        ct_pk_bytes = bytes.fromhex(ct_pk_hex)
                        aesgcm_master = AESGCM(key_material_master)
                        recipient_kem_private_key_bytes = aesgcm_master.decrypt(iv_pk_bytes, ct_pk_bytes, None)
                    else:
                        recipient_kem_private_key_bytes = bytes.fromhex(encrypted_kem_private_key_store)
                except Exception as e_pk_decrypt:
                    app_logger_ref.error(f"PROD: Error decrypting recipient KEM PK for {actual_recipient_username}: {e_pk_decrypt}")
                    socketio.emit('encrypted_message_failed', {'error': 'Server error processing recipient key.', 'client_message_id': client_message_id}, room=current_sid_local)
                    return

            cursor.execute("SELECT dss_public_key FROM users WHERE username = ?", (sender_username_from_auth,))
            sender_db_data = cursor.fetchone()
            if not sender_db_data:
                app_logger_ref.warning(f"Authenticated sender {sender_username_from_auth} not in DB.")
                socketio.emit('encrypted_message_failed', {'error': 'Sender not found.', 'client_message_id': client_message_id}, room=current_sid_local)
                return
            sender_dss_public_key_hex = sender_db_data['dss_public_key']

            if not DEV_MODE:
                try:
                    message_data_to_verify = f"{kem_ciphertext_hex}{iv_hex}{encrypted_message_hex}".encode('utf-8')
                    signature_bytes = bytes.fromhex(signature_hex)
                    sender_dss_public_key_bytes = bytes.fromhex(sender_dss_public_key_hex)
                    dss_verifier = MLDSA_65()
                    if not dss_verifier.verify(public_key=sender_dss_public_key_bytes, message=message_data_to_verify, signature=signature_bytes):
                        raise ValueError("Signature verification failed")
                    app_logger_ref.info(f"Signature verified for {sender_username_from_auth}")
                except Exception as e_sig:
                    app_logger_ref.error(f"Signature verification failed for {sender_username_from_auth}: {e_sig}", exc_info=True)
                    socketio.emit('encrypted_message_failed', {'error': 'Signature verification failed.', 'client_message_id': client_message_id}, room=current_sid_local)
                    return
            else:
                app_logger_ref.warning(f"DEV_MODE: Skipping signature verification for {sender_username_from_auth}")

            decrypted_text: str
            try:
                kem_instance = MLKEM_768()
                kem_ciphertext_bytes = bytes.fromhex(kem_ciphertext_hex)
                shared_key_bytes = kem_instance.decaps(secret_key=recipient_kem_private_key_bytes, cipher_text=kem_ciphertext_bytes)
                aesgcm_decryptor = AESGCM(shared_key_bytes)
                iv_msg_bytes = bytes.fromhex(iv_hex)
                encrypted_msg_bytes = bytes.fromhex(encrypted_message_hex)
                decrypted_message_bytes = aesgcm_decryptor.decrypt(iv_msg_bytes, encrypted_msg_bytes, None)
                decrypted_text = decrypted_message_bytes.decode('utf-8')
                app_logger_ref.info(f"Message from {sender_username_from_auth} to {actual_recipient_username} decrypted: {decrypted_text[:30]}...")
            except Exception as e_decrypt:
                app_logger_ref.error(f"Decryption failed for message to {actual_recipient_username}: {e_decrypt}", exc_info=True)
                if DEV_MODE:
                    decrypted_text = f"[TEST MSG - DECRYPTION FAILED] Raw: {encrypted_message_hex[:100]}..."
                else:
                    socketio.emit('encrypted_message_failed', {'error': 'Message decryption failed.', 'client_message_id': client_message_id}, room=current_sid_local)
                    return
            
            message_to_save = {
                'sender_username': sender_username_from_auth,
                'recipient_username': actual_recipient_username,
                'content': decrypted_text,
                'timestamp': timestamp_from_client,
                'client_message_id': client_message_id,
                'is_read': False
            }
            saved_message_id = save_message(message_to_save)
            app_logger_ref.info(f"Encrypted message (decrypted) from {sender_username_from_auth} to {actual_recipient_username} saved as ID: {saved_message_id}")

            socketio.emit('encrypted_message_sent', {
                'message_id': saved_message_id,
                'client_message_id': client_message_id,
                'recipient_username': actual_recipient_username,
                'timestamp': timestamp_from_client
            }, room=current_sid_local)

            if actual_recipient_username in user_to_sid:
                recipient_sid = user_to_sid[actual_recipient_username]
                full_message_for_recipient = {
                    'id': saved_message_id,
                    'sender_username': sender_username_from_auth,
                    'recipient_username': actual_recipient_username,
                    'content': decrypted_text,
                    'timestamp': timestamp_from_client,
                    'client_message_id': client_message_id,
                    'is_read': False,
                    'isOutgoing': False
                }
                socketio.emit('new_message', full_message_for_recipient, room=recipient_sid)
                socketio.emit('new_message', full_message_for_recipient, room=actual_recipient_username) # Also to username room
                app_logger_ref.info(f"Sent decrypted message {saved_message_id} to online recipient {actual_recipient_username}")
            else:
                app_logger_ref.info(f"Recipient {actual_recipient_username} offline. Message {saved_message_id} stored.")

        except sqlite3.Error as e_sql:
            app_logger_ref.error(f"DB error in _process_encrypted_message_payload: {e_sql}", exc_info=True)
            if conn: conn.rollback()
            socketio.emit('encrypted_message_failed', {'error': 'Database error.', 'client_message_id': client_message_id}, room=current_sid_local)
        except ValueError as e_val:
            app_logger_ref.error(f"Data/Crypto error in _process_encrypted_message_payload: {e_val}", exc_info=True)
            socketio.emit('encrypted_message_failed', {'error': str(e_val), 'client_message_id': client_message_id}, room=current_sid_local)
        except Exception as e_gen:
            app_logger_ref.error(f"Unexpected error in _process_encrypted_message_payload: {e_gen}", exc_info=True)
            if conn: conn.rollback()
            socketio.emit('encrypted_message_failed', {'error': 'Server error processing message.', 'client_message_id': client_message_id}, room=current_sid_local)
        finally:
            if conn:
                conn.close()

    @socketio.on('send_encrypted_message')
    def handle_send_encrypted_message(data: Dict[str, Any]):
        # Accessing app_logger_ref, sid_to_user, user_to_sid, DEV_MODE from the outer scope (register_event_handlers)
        # Accessing socketio from the outer scope (register_event_handlers)
        current_sid = request.sid
        app_logger_ref.info(f"[Thread: {eventlet.getcurrent()}] Received 'send_encrypted_message' from SID {current_sid}")

        if current_sid not in sid_to_user:
            app_logger_ref.warning(f"Unauthenticated SID {current_sid} tried send_encrypted_message.")
            emit('encrypted_message_failed', {'error': 'Not authenticated', 'client_message_id': data.get('client_message_id')})
            return

        sender_username = sid_to_user[current_sid]
        
        recipient_username = data.get('recipient_username')
        kem_ciphertext = data.get('kem_ciphertext')
        iv = data.get('iv')
        encrypted_message = data.get('encrypted_message')
        signature = data.get('signature')
        client_message_id = data.get('client_message_id')
        timestamp = data.get('timestamp', datetime.datetime.now(datetime.timezone.utc).isoformat())

        required_fields = {
            'recipient_username': recipient_username, 'kem_ciphertext': kem_ciphertext,
            'iv': iv, 'encrypted_message': encrypted_message, 'signature': signature
        }
        missing = [f for f, v in required_fields.items() if not v]
        if missing:
            app_logger_ref.warning(f"Missing fields for send_encrypted_message from {sender_username}: {missing}")
            emit('encrypted_message_failed', {'error': f'Missing fields: {", ".join(missing)}', 'client_message_id': client_message_id})
            return

        app_logger_ref.info(f"Spawning async task for encrypted message from {sender_username} to {recipient_username}. ClientMsgID: {client_message_id}")
        eventlet.spawn(
            _process_encrypted_message_payload, # This is the nested helper function
            current_sid, # Pass current_sid explicitly
            sender_username,
            recipient_username,
            kem_ciphertext,
            iv,
            encrypted_message,
            signature,
            client_message_id,
            timestamp
        )


def update_user_list(socketio: SocketIO, app_logger_ref, target_sid=None):
    """
    Update the user list for all clients or a specific client.

    Args:
        socketio: The SocketIO instance.
        app_logger_ref: The application logger.
        target_sid: Optional target socket ID to send to (if None, broadcast to all).
    """
    app_logger_ref.info(f"Updating user list. Target SID: {target_sid if target_sid else 'Broadcast'}")
    
    # Get all currently authenticated and online users from our tracking dictionary
    online_users_list = []
    for username, sid_val in user_to_sid.items(): # user_to_sid maps username to their current SID
        online_users_list.append({
            'username': username,
            'is_online': True,
            'sid': sid_val # Optionally include SID for debugging or advanced client-side logic
        })
    
    # In a more complex application, you might also query the database for users
    # who are not currently in user_to_sid but should appear in the list (e.g., recent contacts).
    # For now, we'll just send the currently online users.
    
    if target_sid:
        app_logger_ref.info(f"Sending user list ({len(online_users_list)} users) to specific SID: {target_sid}")
        socketio.emit('user_list_updated', {'users': online_users_list}, room=target_sid)
    else:
        app_logger_ref.info(f"Broadcasting user list ({len(online_users_list)} users) to all clients.")
        socketio.emit('user_list_updated', {'users': online_users_list}, broadcast=True)
    
    app_logger_ref.info("User list update process complete.")
