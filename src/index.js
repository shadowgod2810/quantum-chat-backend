const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const cors = require('cors');
const dotenv = require('dotenv');
const { PythonShell } = require('python-shell');
const path = require('path');

// Load environment variables
dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    methods: ['GET', 'POST']
  }
});

// Middleware
app.use(cors());
app.use(express.json());

// Initialize PQCrypto
const pqcryptoPath = path.join(__dirname, '../../pqcrypto');
PythonShell.defaultOptions = { pythonPath: process.env.PYTHON_PATH, scriptPath: pqcryptoPath };

// WebSocket connection handling
io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);

  socket.on('message', async (data) => {
    try {
      // Use PQCrypto for message encryption
      const options = {
        mode: 'text',
        pythonOptions: ['-u'],
        args: [data.message, data.recipientPublicKey]
      };

      PythonShell.run('encryption.py', options, (err, results) => {
        if (err) throw err;
        const encryptedMessage = results[0];
        
        // Forward encrypted message to recipient
        io.to(data.recipientId).emit('message', {
          senderId: socket.id,
          content: encryptedMessage
        });
      });
    } catch (error) {
      console.error('Message handling error:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// Start server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
