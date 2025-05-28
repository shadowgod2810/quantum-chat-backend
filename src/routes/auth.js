const express = require('express');
const { v4: uuidv4 } = require('uuid');
const CryptoService = require('../services/crypto');
const db = require('../models/db');

const router = express.Router();

// Register new user
router.post('/register', async (req, res) => {
  try {
    const { username } = req.body;
    
    // Generate KEM and signature keypairs
    const kemPair = await CryptoService.generateKeypair('Kyber512');
    const sigPair = await CryptoService.generateKeypair('Dilithium2');
    
    // Create user
    const userId = uuidv4();
    db.createUser.run(userId, username, kemPair.publicKey, sigPair.publicKey);
    
    res.json({
      id: userId,
      username,
      privateKeys: {
        kem: kemPair.privateKey,
        sig: sigPair.privateKey
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
});

// Login
router.post('/login', async (req, res) => {
  try {
    const { username, publicKey } = req.body;
    
    // Get user
    const user = db.getUserByUsername.get(username);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Create session with shared key
    const sessionId = uuidv4();
    const { ciphertext, sharedKey } = await CryptoService.encapsulateKey(user.public_key_kem);
    
    db.createSession.run(sessionId, user.id, sharedKey);
    
    res.json({
      sessionId,
      ciphertext,
      user: {
        id: user.id,
        username: user.username,
        publicKeyKem: user.public_key_kem,
        publicKeySig: user.public_key_sig
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
});

// Logout
router.post('/logout', (req, res) => {
  try {
    const { sessionId } = req.body;
    db.deleteSession.run(sessionId);
    res.json({ message: 'Logged out successfully' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Logout failed' });
  }
});

module.exports = router;
