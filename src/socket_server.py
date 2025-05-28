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
    # Configure Socket.IO with optimized settings
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",  # Allow all origins for development
        ping_timeout=120,  # Longer ping timeout for better reliability
        ping_interval=15,   # More frequent pings to detect disconnection
        async_mode='eventlet',  # Use eventlet for best performance
        logger=True,  # Enable logging for debugging
        engineio_logger=True  # Enable engine.io logging
    )
    
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
        session_id = data.get('session_id')
        if not session_id:
            emit('authentication_failed', {'message': 'No session ID provided'})
            return
        
        # In a real application, you would validate the session ID against your database
        # For this example, we'll use a simple lookup from the session store
        from app import get_user_by_session  # Import here to avoid circular imports
        
        user = get_user_by_session(session_id)
        if not user:
            emit('authentication_failed', {'message': 'Invalid session ID'})
            return
        
        username = user.get('username')
        
        # Register this socket with the user
        sid_to_user[request.sid] = username
        user_to_sid[username] = request.sid
        
        # Create a personal room for this user
        join_room(username)
        if username not in user_rooms:
            user_rooms[username] = set()
        user_rooms[username].add(username)
        
        print(f"User {username} authenticated with socket ID {request.sid}")
        
        # Notify the client of successful authentication
        emit('authentication_success', {
            'username': username,
            'status': 'authenticated'
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
            return
        
        sender_username = sid_to_user[request.sid]
        recipient_username = data.get('recipient_username')
        message_content = data.get('message')
        client_message_id = data.get('client_message_id')
        timestamp = data.get('timestamp', datetime.datetime.now().isoformat())
        
        if not recipient_username or not message_content:
            emit('error', {'message': 'Missing recipient or message content'})
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
            
            # Send confirmation to sender
            emit('message_sent', {
                'id': saved_id,
                'recipient_username': recipient_username,
                'content': message_content,
                'timestamp': timestamp,
                'client_message_id': client_message_id
            })
            
            # Send message to recipient if they're online
            if recipient_username in user_to_sid:
                recipient_sid = user_to_sid[recipient_username]
                emit('new_message', message, room=recipient_username)
                print(f"Sent message to {recipient_username} in room {recipient_username}")
            else:
                print(f"User {recipient_username} is offline, message saved for later delivery")
            
            # Return success response
            emit('direct_message_response', {'success': True, 'message_id': saved_id})
            
        except Exception as e:
            print(f"Error handling direct message: {e}")
            emit('direct_message_response', {'success': False, 'error': str(e)})
    
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
