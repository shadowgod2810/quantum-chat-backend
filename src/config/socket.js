const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');
const CryptoService = require('../services/crypto');
const db = require('../models/db');

function initializeSocket(server) {
  const io = new Server(server, {
    cors: {
      origin: process.env.FRONTEND_URL || 'http://localhost:3000',
      methods: ['GET', 'POST']
    }
  });

  // Store user socket mappings
  const userSockets = new Map();

  io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    // Handle user authentication
    socket.on('authenticate', ({ userId }) => {
      userSockets.set(userId, socket);
      socket.userId = userId;
      console.log(`User ${userId} authenticated`);
    });

    // Handle messages
    socket.on('message', async (data) => {
      try {
        const { recipientId, content, signature } = data;
        const senderId = socket.userId;

        // Save message to database
        const messageId = uuidv4();
        db.createMessage.run(messageId, senderId, recipientId, content, signature);

        // Forward message to recipient if online
        const recipientSocket = userSockets.get(recipientId);
        if (recipientSocket) {
          recipientSocket.emit('message', {
            id: messageId,
            senderId,
            content,
            signature,
            createdAt: new Date().toISOString()
          });
        }
      } catch (error) {
        console.error('Message handling error:', error);
        socket.emit('error', { message: 'Failed to send message' });
      }
    });

    // Handle disconnection
    socket.on('disconnect', () => {
      if (socket.userId) {
        userSockets.delete(socket.userId);
      }
      console.log('Client disconnected:', socket.id);
    });
  });

  return io;
}

module.exports = initializeSocket;
