"""
Kyber768 key encapsulation mechanism.
"""
from quantcrypt.kem import MLKEM_768

_kyber = MLKEM_768()

def generate_keypair():
    return _kyber.keygen()

def encrypt(public_key):
    return _kyber.encaps(public_key)

def decrypt(private_key, ciphertext):
    return _kyber.decaps(private_key, ciphertext)
