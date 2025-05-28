"""
Digital signature module for Post-Quantum Cryptography.
"""
from quantcrypt.dss import MLDSA_44

SIG_ALGORITHMS = {
    "Dilithium2": MLDSA_44
}

SUPPORTED_SIG_ALGORITHMS = set(SIG_ALGORITHMS.keys())

def sign_message(algorithm: str, private_key: bytes, message: bytes) -> bytes:
    """Sign a message using the given private key.

    Args:
        algorithm (str): The signature algorithm to use.
            Must be one of: Dilithium2
        private_key (bytes): The private key to use for signing.
        message (bytes): The message to sign.

    Returns:
        bytes: The signature.

    Raises:
        ValueError: If the algorithm is not supported
    """
    if algorithm not in SUPPORTED_SIG_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm: {algorithm}. "
            f"Must be one of: {', '.join(sorted(SUPPORTED_SIG_ALGORITHMS))}"
        )
    
    dss = SIG_ALGORITHMS[algorithm]()
    return dss.sign(private_key, message)

def verify_signature(algorithm: str, public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a signature using the given public key.

    Args:
        algorithm (str): The signature algorithm to use.
            Must be one of: Dilithium2
        public_key (bytes): The public key to use for verification.
        message (bytes): The message that was signed.
        signature (bytes): The signature to verify.

    Returns:
        bool: True if the signature is valid, False otherwise.

    Raises:
        ValueError: If the algorithm is not supported
    """
    if algorithm not in SUPPORTED_SIG_ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm: {algorithm}. "
            f"Must be one of: {', '.join(sorted(SUPPORTED_SIG_ALGORITHMS))}"
        )
    
    dss = SIG_ALGORITHMS[algorithm]()
    try:
        dss.verify(public_key, message, signature)
        return True
    except:
        return False
