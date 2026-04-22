"""
DH密钥交换模块
实现X25519 ECDH密钥交换
"""

from cryptography.hazmat.primitives.asymmetric import x25519


def generate_keypair():
    """
    生成X25519密钥对

    Returns:
        Tuple[X25519PrivateKey, X25519PublicKey]: 私钥和公钥
    """
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def dh_exchange(private_key, public_key):
    """
    ECDH密钥交换

    Args:
        private_key: 本地私钥（X25519PrivateKey）
        public_key: 远程公钥（X25519PublicKey）

    Returns:
        bytes: 共享密钥
    """
    shared_secret = private_key.exchange(public_key)
    return shared_secret
