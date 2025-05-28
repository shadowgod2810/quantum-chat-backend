"""
Key generation module for Post-Quantum Cryptography.
"""
from typing import Tuple
from quantcrypt.kem import MLKEM_512, MLKEM_768, MLKEM_1024
from quantcrypt.dss import MLDSA_44

KEM_ALGORITHMS = {
    "Kyber512": MLKEM_512,
    "Kyber768": MLKEM_768,
    "Kyber1024": MLKEM_1024
}

SIG_ALGORITHMS = {
    "Dilithium2": MLDSA_44
}

SUPPORTED_KEM_ALGORITHMS = set(KEM_ALGORITHMS.keys())
SUPPORTED_SIG_ALGORITHMS = set(SIG_ALGORITHMS.keys())
SUPPORTED_ALGORITHMS = SUPPORTED_KEM_ALGORITHMS | SUPPORTED_SIG_ALGORITHMS

def generate_keypair(algorithm: str) -> Tuple[bytes, bytes]:
    """Generate a keypair for the specified algorithm.

    Args:
        algorithm (str): The algorithm to use for key generation.
            Must be one of: Kyber512, Kyber768, Kyber1024, Dilithium2

    Returns:
        Tuple[bytes, bytes]: A tuple containing (public_key, private_key)

    Raises:
        ValueError: If the algorithm is not supported
    """
    if algorithm not in SUPPORTED_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm: {algorithm}. "
            f"Must be one of: {', '.join(sorted(SUPPORTED_ALGORITHMS))}"
        )
    
    if algorithm in SUPPORTED_KEM_ALGORITHMS:
        kem = KEM_ALGORITHMS[algorithm]()
        return kem.keygen()
    elif algorithm in SUPPORTED_SIG_ALGORITHMS:
        dss = SIG_ALGORITHMS[algorithm]()
        return dss.keygen()
    else:
        raise ValueError(
            f"Unsupported algorithm: {algorithm}. "
            f"Must be one of: {', '.join(sorted(SUPPORTED_KEM_ALGORITHMS | SUPPORTED_SIG_ALGORITHMS))}"
        )
