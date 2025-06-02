import os
import json
import uuid
import datetime
from typing import Dict, List, Any, Optional, Set
from flask import Flask, request
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from .database import save_message, get_messages_for_user, mark_messages_as_read, get_recent_conversations

# User session tracking
sid_to_user: Dict[str, str] = {}  # Maps socket ID to username
user_to_sid: Dict[str, str] = {}  # Maps username to socket ID
user_rooms: Dict[str, Set[str]] = {}  # Maps username to set of rooms they're in

def init_socketio(app: Flask) -> SocketIO:
    """Initialize and configure the Socket.IO server"""
    # Get environment setting from app
    environment = os.environ.get('FLASK_ENV', 'development')
    
    # Access the global allowed_origins variable directly from the app module
    # This ensures we're using the same origins as the main Flask app
    import sys
    main_module = sys.modules['__main__']
    
    if hasattr(main_module, 'allowed_origins'):
        allowed_origins = main_module.allowed_origins
        print(f"Using allowed_origins from main module: {allowed_origins}")
    else:
        # Fallback to development mode (allow all origins)
        allowed_origins = '*'
        print("Warning: Could not find allowed_origins in main module, defaulting to '*'")
    
    # Configure Socket.IO with optimized settings
    socketio = SocketIO(
        app,
        cors_allowed_origins=allowed_origins,
        ping_timeout=120,  # Longer ping timeout for better reliability
        ping_interval=15,   # More frequent pings to detect disconnection
        async_mode='eventlet',  # Use eventlet for best performance
        logger=True,  # Enable logging for debugging
        engineio_logger=True,  # Enable engine.io logging
        cookie=False  # Disable cookies to avoid CORS issues
    )
    
    print(f"Socket.IO initialized with CORS allowed origins: {allowed_origins}")
    print(f"Environment: {environment}")
    print(f"Socket.IO configuration: async_mode={socketio.async_mode}")
    
    
    # Register event handlers
    register_event_handlers(socketio)
    
    return socketio

def register_event_handlers(socketio: SocketIO) -> None:
    """Register all Socket.IO event handlers"""
    
    @socketio.on('connect')
    def handle_connect():
        """Handle client connection"""
        print(f"Client connected: {request.sid}")
        emit('connection_established', {'status': 'connected'})
    
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
        """Handle user authentication"""
        print(f"Authentication attempt from socket {request.sid}")
        print(f"Auth data: {data}")
        
        # Check if this socket is already authenticated
        if request.sid in sid_to_user:
            username = sid_to_user[request.sid]
            print(f"Socket {request.sid} already authenticated as {username}")
            emit('authentication_success', {
                'username': username,
                'status': 'authenticated',
                'message': 'Already authenticated'
            })
            return
        
        # Get session ID from data or from auth header
        session_id = data.get('session_id')
        if not session_id and 'token' in data:
            session_id = data.get('token')  # Try alternative key
        
        # Check for auth header if not in data
        if not session_id and request.headers.get('Authorization'):
            auth_header = request.headers.get('Authorization')
            if auth_header.startswith('Bearer '):
                session_id = auth_header.split(' ')[1]
        
        if not session_id:
            print(f"No session ID provided for socket {request.sid}")
            emit('authentication_failed', {'message': 'No session ID provided'})
            return
        
        print(f"Validating session ID for socket {request.sid}")
        
        # In a real application, you would validate the session ID against your database
        # For this example, we'll use a simple lookup from the session store
        from app import get_user_by_session  # Import here to avoid circular imports
        
        user = get_user_by_session(session_id)
        if not user:
            print(f"Invalid session ID for socket {request.sid}")
            emit('authentication_failed', {'message': 'Invalid session ID'})
            return
        
        username = user.get('username')
        print(f"Found user {username} for session ID")
        
        # Check if user is already connected with another socket
        if username in user_to_sid:
            old_sid = user_to_sid[username]
            if old_sid != request.sid:
                print(f"User {username} already connected with socket {old_sid}, updating to {request.sid}")
                # Remove old socket mapping
                if old_sid in sid_to_user:
                    del sid_to_user[old_sid]
        
        # Register this socket with the user
        sid_to_user[request.sid] = username
        user_to_sid[username] = request.sid
        
        # Create a personal room for this user
        join_room(username)
        if username not in user_rooms:
            user_rooms[username] = set()
        user_rooms[username].add(username)
        
        print(f"User {username} authenticated with socket ID {request.sid}")
        print(f"Current online users: {list(user_to_sid.keys())}")
        
        # Notify the client of successful authentication
        # Send both 'authenticated' (for frontend) and 'authentication_success' (for backward compatibility)
        emit('authenticated', {
            'username': username,
            'status': 'authenticated',
            'message': 'Authentication successful'
        })
        
        # Also emit the original event for backward compatibility
        emit('authentication_success', {
            'username': username,
            'status': 'authenticated',
            'message': 'Authentication successful'
        })
        
        # Notify other users about this user coming online
        emit('user_online', {'username': username}, broadcast=True, include_self=False)
        
        # Update the user list for all clients
        update_user_list(socketio)
    
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
        """Handle request for recent conversations"""
        # Check if user is authenticated
        if request.sid not in sid_to_user:
            emit('error', {'message': 'Not authenticated'})
            return
        
        username = sid_to_user[request.sid]
        
        try:
            # Get recent conversations from database
            conversations = get_recent_conversations(username)
            
            # Send to client
            emit('recent_conversations', {'conversations': conversations})
            
        except Exception as e:
            print(f"Error getting recent conversations: {e}")
            emit('error', {'message': f'Error getting recent conversations: {str(e)}'})
    
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

def update_user_list(socketio: SocketIO, target=None):
    """
    Update the user list for all clients or a specific client
    
    Args:
        socketio: The SocketIO instance
        target: Optional target socket ID to send to (if None, broadcast to all)
    """
    # Get all authenticated users
    users = []
    for username, sid in user_to_sid.items():
        users.append({
            'username': username,
            'is_online': True
        })
    
    # Add some offline users from the database (in a real app)
    # This would query your user database for recently active users
    
    # Send the user list
    if target:
        socketio.emit('update_user_list', users, room=target)
    else:
        socketio.emit('update_user_list', users, broadcast=True)
