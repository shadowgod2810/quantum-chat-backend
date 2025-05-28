"""
Dilithium2 digital signature algorithm.
"""
from quantcrypt.dss import MLDSA_65

_dilithium = MLDSA_65()

def generate_keypair():
    return _dilithium.keygen()

def sign(private_key, message):
    return _dilithium.sign(private_key, message)

def verify(public_key, message, signature):
    return _dilithium.verify(public_key, message, signature)
