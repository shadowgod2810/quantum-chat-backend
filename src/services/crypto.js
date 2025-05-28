const { PythonShell } = require('python-shell');
const path = require('path');

const pqcryptoPath = path.join(__dirname, '../../../pqcrypto');
PythonShell.defaultOptions = { pythonPath: process.env.PYTHON_PATH, scriptPath: pqcryptoPath };

class CryptoService {
  static async generateKeypair(algorithm) {
    return new Promise((resolve, reject) => {
      PythonShell.run('keygen.py', {
        args: [algorithm]
      }, (err, results) => {
        if (err) reject(err);
        const [publicKey, privateKey] = results;
        resolve({ publicKey, privateKey });
      });
    });
  }

  static async encryptMessage(message, recipientPublicKey, senderPrivateKey) {
    return new Promise((resolve, reject) => {
      PythonShell.run('encryption.py', {
        args: ['encrypt', message, recipientPublicKey, senderPrivateKey]
      }, (err, results) => {
        if (err) reject(err);
        const [ciphertext, signature] = results;
        resolve({ ciphertext, signature });
      });
    });
  }

  static async decryptMessage(ciphertext, signature, senderPublicKey, recipientPrivateKey) {
    return new Promise((resolve, reject) => {
      PythonShell.run('encryption.py', {
        args: ['decrypt', ciphertext, signature, senderPublicKey, recipientPrivateKey]
      }, (err, results) => {
        if (err) reject(err);
        const [plaintext] = results;
        resolve(plaintext);
      });
    });
  }

  static async encapsulateKey(recipientPublicKey) {
    return new Promise((resolve, reject) => {
      PythonShell.run('kem.py', {
        args: ['encapsulate', recipientPublicKey]
      }, (err, results) => {
        if (err) reject(err);
        const [ciphertext, sharedKey] = results;
        resolve({ ciphertext, sharedKey });
      });
    });
  }

  static async decapsulateKey(ciphertext, recipientPrivateKey) {
    return new Promise((resolve, reject) => {
      PythonShell.run('kem.py', {
        args: ['decapsulate', ciphertext, recipientPrivateKey]
      }, (err, results) => {
        if (err) reject(err);
        const [sharedKey] = results;
        resolve(sharedKey);
      });
    });
  }
}

module.exports = CryptoService;
