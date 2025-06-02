#!/usr/bin/env python
# server.py - Dedicated server script for Flask-SocketIO with eventlet

# Monkey patch at the very beginning before any other imports
import eventlet
eventlet.monkey_patch()

import os
import sys
import logging
from logging.handlers import RotatingFileHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)
logger.info("Starting QuantumChat server with eventlet")

# Import the Flask app and SocketIO instance
from app import app, socketio

if __name__ == '__main__':
    # Get port from environment variable or use default
    port = int(os.environ.get('PORT', 10000))
    
    # Log important configuration
    logger.info(f"Environment: {os.environ.get('FLASK_ENV', 'development')}")
    logger.info(f"Debug mode: {app.debug}")
    logger.info(f"Starting server on port: {port}")
    
    # Run the SocketIO server with eventlet
    socketio.run(
        app,
        host='0.0.0.0',
        port=port,
        debug=False,  # Set to False in production
        use_reloader=False,  # Set to False in production
        log_output=True,
        cors_allowed_origins='*'  # This will be overridden by the app's configuration
    )
