"""
Symmetric encryption module using AES-GCM for Post-Quantum Cryptography.
"""
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def encrypt_message(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt using AES-GCM with a PQC-derived symmetric key.
    
    Args:
        key: 32-byte symmetric key (e.g., from KEM shared secret)
        plaintext: Message bytes to encrypt
    
    Returns:
        bytes: Encrypted message (nonce || ciphertext || tag)
    
    Raises:
        ValueError: If key length is not 32 bytes
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    
    # Generate random 96-bit nonce
    nonce = secrets.token_bytes(12)
    
    # Create AESGCM instance and encrypt
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    
    # Return nonce || ciphertext || tag
    return nonce + ciphertext

def decrypt_message(key: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt using AES-GCM.
    
    Args:
        key: 32-byte symmetric key (same as used for encryption)
        ciphertext: Encrypted message bytes from encrypt_message()
    
    Returns:
        bytes: Decrypted message
    
    Raises:
        ValueError: If key length is not 32 bytes or ciphertext is too short
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(ciphertext) < 28:  # 12 (nonce) + 16 (tag) minimum
        raise ValueError("Invalid ciphertext")
    
    # Split nonce and ciphertext
    nonce = ciphertext[:12]
    encrypted_data = ciphertext[12:]
    
    # Decrypt
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, encrypted_data, None)
        return plaintext
    except Exception as e:
        raise ValueError("Decryption failed") from e
