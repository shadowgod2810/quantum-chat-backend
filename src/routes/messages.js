const express = require('express');
const { v4: uuidv4 } = require('uuid');
const CryptoService = require('../services/crypto');
const db = require('../models/db');

const router = express.Router();

// Get chat history
router.get('/:userId', (req, res) => {
  try {
    const { userId } = req.params;
    const { recipientId, limit = 50 } = req.query;
    
    const messages = db.getMessages.all(userId, recipientId, recipientId, userId, limit);
    
    res.json(messages);
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Failed to get messages' });
  }
});

// Mark message as read
router.post('/:messageId/read', (req, res) => {
  try {
    const { messageId } = req.params;
    const { userId } = req.body;
    
    db.markMessageAsRead.run(messageId, userId);
    
    res.json({ message: 'Message marked as read' });
  } catch (error) {
    console.error('Mark read error:', error);
    res.status(500).json({ error: 'Failed to mark message as read' });
  }
});

module.exports = router;
