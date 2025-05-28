"""
Key Encapsulation Mechanism (KEM) module for Post-Quantum Cryptography.
"""
from typing import Tuple
from quantcrypt.kem import MLKEM_512, MLKEM_768, MLKEM_1024

KEM_ALGORITHMS = {
    "Kyber512": MLKEM_512,
    "Kyber768": MLKEM_768,
    "Kyber1024": MLKEM_1024
}

SUPPORTED_KEM_ALGORITHMS = set(KEM_ALGORITHMS.keys())

def encapsulate_key(algorithm: str, public_key: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate a shared secret using the given public key.

    Args:
        algorithm (str): The KEM algorithm to use.
            Must be one of: Kyber512, Kyber768, Kyber1024
        public_key (bytes): The public key to use for encapsulation.

    Returns:
        Tuple[bytes, bytes]: A tuple containing (ciphertext, shared_secret)

    Raises:
        ValueError: If the algorithm is not supported
    """
    if algorithm not in SUPPORTED_KEM_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm: {algorithm}. "
            f"Must be one of: {', '.join(sorted(SUPPORTED_KEM_ALGORITHMS))}"
        )
    
    kem = KEM_ALGORITHMS[algorithm]()
    return kem.encaps(public_key)

def decapsulate_key(algorithm: str, ciphertext: bytes, private_key: bytes) -> bytes:
    """Decapsulate a shared secret using the given private key.

    Args:
        algorithm (str): The KEM algorithm to use.
            Must be one of: Kyber512, Kyber768, Kyber1024
        ciphertext (bytes): The ciphertext to decapsulate.
        private_key (bytes): The private key to use for decapsulation.

    Returns:
        bytes: The shared secret.

    Raises:
        ValueError: If the algorithm is not supported
    """
    if algorithm not in SUPPORTED_KEM_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm: {algorithm}. "
            f"Must be one of: {', '.join(sorted(SUPPORTED_KEM_ALGORITHMS))}"
        )
    
    kem = KEM_ALGORITHMS[algorithm]()
    return kem.decaps(private_key, ciphertext)
