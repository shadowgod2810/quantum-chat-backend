"""
Post-Quantum Cryptography Library for secure messaging applications.
Implements NIST-recommended PQC algorithms using quantcrypt.
"""

from pqcrypto.keygen import generate_keypair, SUPPORTED_KEM_ALGORITHMS, SUPPORTED_SIG_ALGORITHMS
from pqcrypto.kem import encapsulate_key, decapsulate_key
from pqcrypto.sign import sign_message, verify_signature

__version__ = "0.1.0"

__all__ = [
    'generate_keypair',
    'encapsulate_key',
    'decapsulate_key',
    'sign_message',
    'verify_signature',
    'SUPPORTED_KEM_ALGORITHMS',
    'SUPPORTED_SIG_ALGORITHMS'
]
