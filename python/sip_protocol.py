from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import os

# 身份密钥（持久化）
identity_private_a = x25519.X25519PrivateKey.generate()
identity_public_a = identity_private_a.public_key()
identity_pub_bytes = identity_public_a.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

# 临时密钥（每次握手不同）
ephemeral_private_a = x25519.X25519PrivateKey.generate()
ephemeral_public_a = ephemeral_private_a.public_key()
ephemeral_pub_bytes = ephemeral_public_a.public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
)

# Nonce
nonce_a = os.urandom(16)


from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import hashlib
import hmac
import time
from argon2 import PasswordHasher

# 三重 DH 密钥交换（按发起方视角定义）
# 发起方（A）计算：
#   shared_1 = identity_private_a × ephemeral_public_b (发起方身份 × 响应方临时)
#   shared_2 = ephemeral_private_a × identity_public_b (发起方临时 × 响应方身份)
#   shared_3 = ephemeral_private_a × ephemeral_public_b (发起方临时 × 响应方临时)
# 响应方（B）计算：
#   shared_1 = identity_private_b × ephemeral_public_a (响应方身份 × 发起方临时)
#   shared_2 = ephemeral_private_b × identity_public_a (响应方临时 × 发起方身份)
#   shared_3 = ephemeral_private_b × ephemeral_public_a (响应方临时 × 发起方临时)
# 注意：由于X25519的对称性，shared_1和shared_2在双方视角下是交换的
# 但必须按照相同的顺序组合，才能派生出相同的会话密钥
shared_1 = identity_local * remote_ephemeral  # 本地身份 * 远程临时
shared_2 = ephemeral_local * remote_identity  # 本地临时 * 远程身份
shared_3 = ephemeral_local * remote_ephemeral  # 本地临时 * 远程临时

# PSK 哈希（防止 MITM 攻击）
psk = b"<YOUR_PRE_SHARED_KEY_HERE>"  # 从配置或环境变量获取
ph = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,  # 64MB
    parallelism=4,
    hash_len=32,
    salt_len=16
)
psk_hash = ph.hash(psk).encode('latin-1')  # Argon2id 输出

# 组合共享密钥 + 双方 nonce + PSK（按发起方、响应方顺序）
combined = shared_1 + shared_2 + shared_3 + initiator_nonce + responder_nonce + psk_hash

# 派生三个独立密钥
hkdf = HKDF(
    algorithm=hashes.SHA256(),
    length=96,  # 3 × 32 bytes
    salt=b"SIPHandshake",
    info=b"session-keys"
)
key_material = hkdf.derive(combined)

encryption_key = key_material[0:32]
auth_key = key_material[32:64]
replay_key = key_material[64:96]

# 生成 HMAC 签名
auth_data = {
    "ephemeral_pub": ephemeral_pub_bytes.hex(),
    "nonce": nonce_b.hex(),
    "timestamp": int(time.time() * 1000)  # 毫秒
}
auth_json = json.dumps(auth_data).encode()
signature = hmac.new(auth_key, auth_json, hashlib.sha256).digest()


from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# XChaCha20-Poly1305
cipher = ChaCha20Poly1305(session_key)
ciphertext = cipher.encrypt(nonce, plaintext, None)

# ciphertext 最后 16 bytes 是 auth_tag
encrypted_bytes = ciphertext[:-16]
auth_tag = ciphertext[-16:]


# Python
class NonceManager:
    def __init__(self):
        self.used_nonces = set()

    def check_and_add(self, nonce: bytes) -> bool:
        if nonce in self.used_nonces:
            return False
        self.used_nonces.add(nonce)
        if len(self.used_nonces) > 1000:
            self.used_nonces.pop()  # 移除最旧的
        return True


def generate_replay_tag(replay_key: bytes, sender_id: str, message_counter: int) -> str:
    """
    使用 replay_key 生成防重放标记
    
    Args:
        replay_key: 从 HKDF 派生的 replay_key (32 bytes)
        sender_id: 发送方 ID
        message_counter: 消息计数器
        
    Returns:
        HMAC-SHA256 的十六进制字符串
    """
    import hmac
    import hashlib
    
    data = f"{sender_id}:{message_counter}".encode()
    signature = hmac.new(replay_key, data, hashlib.sha256).digest()
    return signature.hex()


def verify_replay_tag(
    replay_key: bytes,
    sender_id: str,
    message_counter: int,
    replay_tag: str
) -> bool:
    """
    使用 replay_key 验证防重放标记
    
    Args:
        replay_key: 从 HKDF 派生的 replay_key (32 bytes)
        sender_id: 发送方 ID
        message_counter: 消息计数器
        replay_tag: 消息中的 replay_tag 字段
        
    Returns:
        True if valid, False if invalid
    """
    import hmac
    import hashlib
    
    expected_tag = generate_replay_tag(replay_key, sender_id, message_counter)
    return hmac.compare_digest(expected_tag, replay_tag)


import time

def validate_timestamp(ts: int) -> bool:
    # 时间戳单位：毫秒
    now = int(time.time() * 1000)
    return abs(now - ts) <= 5 * 60 * 1000  # ±5 minutes


import hashlib

def generate_fragment_id(message_counter: int, sender_id: str) -> str:
    """
    生成分片ID
    
    Args:
        message_counter: 消息计数器
        sender_id: 发送方ID
        
    Returns:
        fragment_id: 分片ID（16字符十六进制字符串）
    """
    data = f"{sender_id}:{message_counter}".encode()
    fragment_id = hashlib.sha256(data).hexdigest()[:16]
    return fragment_id


import json
import base64

def serialize_session_state(state: dict) -> str:
    """
    序列化会话状态为JSON字符串
    
    Args:
        state: 会话状态字典
        
    Returns:
        serialized: Base64编码的JSON字符串
    """
    json_str = json.dumps(state)
    serialized = base64.b64encode(json_str.encode()).decode()
    return serialized

def deserialize_session_state(serialized: str) -> dict:
    """
    反序列化会话状态
    
    Args:
        serialized: Base64编码的JSON字符串
        
    Returns:
        state: 会话状态字典
    """
    json_str = base64.b64decode(serialized).decode()
    state = json.loads(json_str)
    return state


state = deserialize_session_state(serialized_state)


def verify_session_resume(message: dict, auth_key: bytes) -> bool:
    """
    验证Session_Resume消息签名
    
    Args:
        message: Session_Resume消息
        auth_key: 当前auth_key
        
    Returns:
        valid: 是否有效
    """
    data = f"{message['sender_id']}:{message['message_counter']}".encode()
    expected_sig = hmac.new(auth_key, data, hashlib.sha256).digest()
    actual_sig = base64.b64decode(message['signature'])
    return hmac.compare_digest(expected_sig, actual_sig)


serialized_state = serialize_session_state(state)
# 保存到本地存储（数据库、文件等）


# 协议版本
PROTOCOL_VERSION = "SIP-1.0"

# 非对称加密
ECDH_ALGORITHM = "X25519"
PUBLIC_KEY_LENGTH = 32
PRIVATE_KEY_LENGTH = 32

# 对称加密
CIPHER_ALGORITHM = "XChaCha20-Poly1305"
SESSION_KEY_LENGTH = 32

# Nonce 长度（统一）
NONCE_LENGTH = 24           # 消息加密 nonce (XChaCha20 需要 24 bytes)
HANDSHAKE_NONCE_LENGTH = 16  # 握手 nonce
REKEY_NONCE_LENGTH = 16     # Rekey nonce

# 密钥派生
KDF_ALGORITHM = "HKDF-SHA256"
KDF_SALT = b"SIPHandshake"
KDF_INFO = b"session-keys"

# PSK 哈希
PSK_HASH_ALGORITHM = "Argon2id"
PSK_HASH_LENGTH = 32
PSK_SALT_LENGTH = 16

# 时间戳
TIMESTAMP_UNIT = "milliseconds"  # 统一使用毫秒

# 消息限制
MAX_MESSAGE_SIZE = 1024 * 1024  # 1MB
MAX_PAYLOAD_SIZE = 900 * 1024    # 900KB


# 预共享密钥
psk = b"0123456789ABCDEF0123456789ABCDEF"  # 32 bytes

# Agent A 密钥对
identity_private_a = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
identity_public_a = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
ephemeral_private_a = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
ephemeral_public_a = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")

# Agent B 密钥对
identity_private_b = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
identity_public_b = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
ephemeral_private_b = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
ephemeral_public_b = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")

# Nonce
nonce_a = bytes.fromhex("000102030405060708090a0b0c0d0e0f")  # 16 bytes
nonce_b = bytes.fromhex("101112131415161718191a1b1c1d1e1f")  # 16 bytes

# 期望输出（需要计算）
# 1. 三重DH密钥交换
shared_1 = x25519.X25519PrivateKey.from_private_bytes(identity_private_a).exchange(
    x25519.X25519PublicKey.from_public_bytes(ephemeral_public_b)
)
shared_2 = x25519.X25519PrivateKey.from_private_bytes(ephemeral_private_a).exchange(
    x25519.X25519PublicKey.from_public_bytes(identity_public_b)
)
shared_3 = x25519.X25519PrivateKey.from_private_bytes(ephemeral_private_a).exchange(
    x25519.X25519PublicKey.from_public_bytes(ephemeral_public_b)
)

# 2. 组合共享密钥
shared_secret = shared_1 + shared_2 + shared_3  # 96 bytes

# 3. PSK哈希（Argon2id）
# 注意：Argon2id使用随机盐，每次哈希结果不同
# 测试时使用固定盐以确保可复现
psk_salt_fixed = b"0123456789ABCDEF"  # 16 bytes（测试固定盐）

# 手动计算Argon2id哈希（使用固定盐）
# 以下哈希值是使用固定盐psk_salt_fixed计算的预计算值
psk_hash_fixed = bytes.fromhex("a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0")  # 示例值

# 实际实现中应使用：
psk_hash, salt = hash_psk(psk, psk_salt_fixed)
# 测试时验证psk_hash与psk_hash_fixed一致

# 4. HKDF派生
ikm = shared_secret + psk_hash_fixed + nonce_a + nonce_b  # 176 bytes
kdf = HKDF(
    algorithm=hashes.SHA256(),
    length=96,  # 3 * 32 bytes
    salt=KDF_SALT,
    info=KDF_INFO,
)
session_key = kdf.derive(ikm)
encryption_key = session_key[:32]  # 前32字节
auth_key = session_key[32:64]  # 中间32字节
replay_key = session_key[64:96]  # 后32字节

# 5. 期望输出（固定十六进制值）
# 注意：由于Argon2id使用随机盐，实际实现需要使用固定盐才能复现
shared_secret_expected = shared_secret.hex()  # 可以计算
psk_hash_expected = psk_hash_fixed.hex()  # 固定值（示例）
session_key_expected = session_key.hex()  # 可以计算
encryption_key_expected = encryption_key.hex()  # 可以计算
auth_key_expected = auth_key.hex()  # 可以计算
replay_key_expected = replay_key.hex()  # 可以计算

# 实际测试步骤：
# 1. 使用固定盐psk_salt_fixed调用hash_psk(psk, psk_salt_fixed)
# 2. 验证输出psk_hash与psk_hash_fixed一致
# 3. 使用psk_hash_fixed计算HKDF
# 4. 验证输出的session_key与session_key_expected一致


# 输入
encryption_key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")
plaintext = b"Hello, SIP!"
nonce = bytes.fromhex("000000000000000000000000000000000000000000000000")  # 24 bytes

# 加密
iv = nonce  # XChaCha20 使用 24 bytes nonce
cipher = ChaCha20Poly1305(encryption_key)
ciphertext_with_tag = cipher.encrypt(iv, plaintext, None)
ciphertext = ciphertext_with_tag[:len(plaintext)]
auth_tag = ciphertext_with_tag[len(plaintext):]

# 期望输出（固定十六进制值）
iv_expected = iv.hex()  # "000000000000000000000000000000000000000000000000"
auth_tag_expected = auth_tag.hex()  # ChaCha20Poly1305认证标签（16 bytes）
ciphertext_expected = ciphertext.hex()  # 加密后的密文

# 说明：
# - iv是明文nonce，可以直接计算
# - auth_tag和ciphertext由ChaCha20Poly1305算法生成，固定输入下输出固定
# - 实际测试时运行加密代码，验证输出与期望值一致


from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import hmac
import time

# 常量
PROTOCOL_VERSION = "SIP-1.0"
KDF_SALT = b"SIPHandshake"
KDF_INFO = b"session-keys"
NONCE_LENGTH = 24
HANDSHAKE_NONCE_LENGTH = 16

# 密钥对生成
def generate_keypair():
    """生成 X25519 密钥对"""
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

# PSK 哈希（Argon2id）
def hash_psk(psk: bytes, salt: bytes = None) -> bytes:
    """
    使用 Argon2id 哈希 PSK
    
    Args:
        psk: 预共享密钥 (任意长度)
        salt: 盐（可选，如果为None则生成随机盐，16 bytes）
        
    Returns:
        psk_hash: 32 bytes 哈希值
        
    需要安装: pip install argon2-cffi
    """
    from argon2 import PasswordHasher, low_level
    import os
    
    # 如果没有提供盐，生成随机盐
    if salt is None:
        salt = os.urandom(16)
    
    # 使用低级API直接计算哈希（避免格式化）
    psk_hash = low_level.hash_secret_raw(
        secret=psk,
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=4,
        hash_len=32,
        type=low_level.Type.ID
    )
    
    return psk_hash, salt

# DH 密钥交换
def dh_exchange(private_key, public_key):
    """ECDH 密钥交换"""
    shared_secret = private_key.exchange(public_key)
    return shared_secret

# HKDF 密钥派生
def derive_keys(shared_secret, psk_hash, nonce_a, nonce_b):
    """派生三个独立密钥"""
    ikm = shared_secret + psk_hash + nonce_a + nonce_b
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=96,  # 3 * 32 bytes
        salt=KDF_SALT,
        info=KDF_INFO,
    )
    keys = kdf.derive(ikm)
    encryption_key = keys[:32]
    auth_key = keys[32:64]
    replay_key = keys[64:96]
    return encryption_key, auth_key, replay_key

# 加密消息
def encrypt_message(encryption_key, plaintext, sender_id, message_counter):
    """加密消息并生成认证标签"""
    nonce = b'0' * NONCE_LENGTH  # 实际应使用随机 nonce
    cipher = ChaCha20Poly1305(encryption_key)
    ciphertext = cipher.encrypt(nonce, plaintext, None)
    # ciphertext = ciphertext[:len(plaintext)] + auth_tag
    return nonce, ciphertext

# 验证消息
def verify_message(auth_key, ciphertext, nonce, expected_tag):
    """验证消息完整性"""
    # 实现取决于具体加密库
    pass

# 生成防重放标签
def generate_replay_tag(replay_key, sender_id, message_counter):
    """生成 HMAC-SHA256 防重放标签"""
    data = sender_id.encode() + str(message_counter).encode()
    tag = hmac.new(replay_key, data, hashes.SHA256()).digest()
    return tag.hex()

# 完整握手流程示例
def handshake(agent_a, agent_b, psk):
    """完整握手流程"""
    # 1. Agent A 发起握手
    nonce_a = b'0' * HANDSHAKE_NONCE_LENGTH
    # ... 实现 Handshake_Hello
    
    # 2. Agent B 响应
    nonce_b = b'0' * HANDSHAKE_NONCE_LENGTH
    # ... 实现 Handshake_Auth
    
    # 3. Agent A 完成握手
    # ... 实现 Handshake_Complete
    
    # 4. 派生会话密钥
    psk_hash, psk_salt = hash_psk(psk)  # 使用 Argon2id 哈希
    encryption_key, auth_key, replay_key = derive_keys(
        shared_secret, psk_hash, nonce_a, nonce_b
    )
    
    return encryption_key, auth_key, replay_key


def send_group_message(plaintext: str, sending_chain: dict) -> (bytes, dict):
    """
    发送群组消息
    
    Args:
        plaintext: 明文消息
        sending_chain: 发送链状态
        
    Returns:
        ciphertext: 密文
        updated_chain: 更新后的发送链状态
    """
    # 1. 派生消息密钥
    message_key = hkdf(
        ikm=sending_chain["chain_key"],
        salt=b"",
        info=b"message-key",
        length=32
    )
    
    # 2. 推进链密钥
    next_chain_key = hkdf(
        ikm=sending_chain["chain_key"],
        salt=b"",
        info=b"chain-key",
        length=32
    )
    
    # 3. 加密消息
    ciphertext = encrypt_aes_gcm(
        key=message_key,
        plaintext=plaintext.encode()
    )
    
    # 4. 更新发送链状态
    updated_chain = {
        "chain_key": next_chain_key,
        "message_number": sending_chain["message_number"] + 1
    }
    
    return ciphertext, updated_chain


def receive_group_message(
    ciphertext: bytes, 
    message_number: int,
    receiving_chain: dict
) -> (str, dict):
    """
    接收群组消息
    
    Args:
        ciphertext: 密文
        message_number: 消息序号（发送方）
        receiving_chain: 接收链状态
        
    Returns:
        plaintext: 明文
        updated_chain: 更新后的接收链状态
    """
    expected_msg_num = receiving_chain["message_number"]
    
    # 检查是否是乱序消息（消息序号大于期望序号）
    if message_number > expected_msg_num:
        # 预先生成跳跃密钥（Skip Ratchet算法）
        # 需要预生成从expected_msg_num到message_number的所有跳跃密钥
        for i in range(expected_msg_num, message_number):
            if i not in receiving_chain["skip_keys"]:
                # 为每一条缺失的消息生成跳跃密钥
                skipped_key = hkdf(
                    ikm=receiving_chain["chain_key"],
                    salt=b"",
                    info=b"message-key",
                    length=32
                )
                receiving_chain["skip_keys"][i] = skipped_key
                
                # 推进链密钥
                next_chain_key = hkdf(
                    ikm=receiving_chain["chain_key"],
                    salt=b"",
                    info=b"chain-key",
                    length=32
                )
                receiving_chain["chain_key"] = next_chain_key
        
        # 使用目标message_number对应的跳跃密钥
        message_key = receiving_chain["skip_keys"][message_number]
        
        # 清理已使用的跳跃密钥
        del receiving_chain["skip_keys"][message_number]
        
    elif message_number == expected_msg_num:
        # 顺序消息，使用当前链密钥
        message_key = hkdf(
            ikm=receiving_chain["chain_key"],
            salt=b"",
            info=b"message-key",
            length=32
        )
        
        # 推进链密钥
        next_chain_key = hkdf(
            ikm=receiving_chain["chain_key"],
            salt=b"",
            info=b"chain-key",
            length=32
        )
        receiving_chain["chain_key"] = next_chain_key
        
    else:
        # 重复消息或过期消息，拒绝
        raise ValueError(f"Invalid message number: {message_number}, expected: {expected_msg_num}")
    
    # 解密消息
    plaintext = decrypt_aes_gcm(
        key=message_key,
        ciphertext=ciphertext
    )
    
    # 更新接收链状态
    updated_chain = {
        "chain_key": receiving_chain["chain_key"],
        "message_number": expected_msg_num + 1,
        "skip_keys": receiving_chain["skip_keys"]
    }
    
    return plaintext.decode(), updated_chain


import json

def initialize_group_chains(members: list, root_key: bytes) -> dict:
    """
    初始化群组链密钥
    
    Args:
        members: 群组成员列表
        root_key: 根密钥
        
    Returns:
        chains: 每个成员的链密钥
    """
    chains = {}
    
    for member in members:
        # 派生sending chain key
        sending_chain_key = hkdf(
            ikm=root_key,
            salt=f"{member}:sending".encode(),
            info=b"sending-chain",
            length=32
        )
        
        # 派生receiving chain key
        receiving_chain_key = hkdf(
            ikm=root_key,
            salt=f"{member}:receiving".encode(),
            info=b"receiving-chain",
            length=32
        )
        
        chains[member] = {
            "sending_chain": {
                "chain_key": sending_chain_key,
                "message_number": 0
            },
            "receiving_chain": {
                "chain_key": receiving_chain_key,
                "message_number": 0,
                "skip_keys": {}
            }
        }
    
    return chains


def update_group_root_key(current_root_key: bytes, new_member_public_key: bytes) -> bytes:
    """
    更新群组root key（成员加入）
    
    Args:
        current_root_key: 当前root key
        new_member_public_key: 新成员的公钥
        
    Returns:
        new_root_key: 新root key
    """
    # 执行DH密钥交换
    shared_secret = dh_exchange(
        private_key=current_root_key,
        public_key=new_member_public_key
    )
    
    # 派生新root key
    new_root_key = hkdf(
        ikm=shared_secret,
        salt=b"",
        info=b"new-root-key",
        length=32
    )
    
    return new_root_key


def update_root_key_after_leave(current_root_key: bytes) -> bytes:
    """
    更新群组root key（成员离开）
    
    Args:
        current_root_key: 当前root key
        
    Returns:
        new_root_key: 新root key
    """
    # 生成新的DH密钥对
    new_dh_keypair = generate_dh_keypair()
    
    # 执行DH密钥交换
    shared_secret = dh_exchange(
        private_key=current_root_key,
        public_key=new_dh_keypair["public_key"]
    )
    
    # 派生新root key
    new_root_key = hkdf(
        ikm=shared_secret,
        salt=b"",
        info=b"new-root-key-after-leave",
        length=32
    )
    
    return new_root_key


def send_group_message(plaintext: str, group_state: dict, sender_id: str) -> str:
    """
    发送群组消息
    
    Args:
        plaintext: 明文消息
        group_state: 群组状态
        sender_id: 发送方ID
        
    Returns:
        message: 群组消息（JSON字符串）
    """
    # 1. 获取发送方的sending chain
    sending_chain = group_state["members"][sender_id]["sending_chain"]
    
    # 2. 派生消息密钥
    message_key = hkdf(
        ikm=sending_chain["chain_key"],
        salt=b"",
        info=b"message-key",
        length=32
    )
    
    # 3. 推进链密钥
    next_chain_key = hkdf(
        ikm=sending_chain["chain_key"],
        salt=b"",
        info=b"chain-key",
        length=32
    )
    
    # 4. 加密消息
    iv = os.urandom(12)  # AES-GCM需要12字节nonce
    ciphertext, auth_tag = encrypt_aes_gcm(
        key=message_key,
        iv=iv,
        plaintext=plaintext.encode()
    )
    
    # 5. 发送方签名
    sender_signature = hmac.new(
        key=message_key,
        msg=ciphertext,
        digestmod=hashlib.sha256
    ).digest()
    
    # 6. 更新sending chain状态
    group_state["members"][sender_id]["sending_chain"] = {
        "chain_key": next_chain_key,
        "message_number": sending_chain["message_number"] + 1
    }
    
    # 7. 构建群组消息
    message = {
        "version": "SIP-1.0",
        "type": "group_message",
        "timestamp": int(time.time() * 1000),
        "sender_id": sender_id,
        "group_id": group_state["group_id"],
        "message_number": sending_chain["message_number"],
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "auth_tag": base64.b64encode(auth_tag).decode(),
        "sender_signature": base64.b64encode(sender_signature).decode()
    }
    
    return json.dumps(message)


def receive_group_message(message: str, group_state: dict, recipient_id: str) -> str:
    """
    接收群组消息（完整版，支持乱序消息）
    
    Args:
        message: 群组消息（JSON字符串）
        group_state: 群组状态
        recipient_id: 接收方ID
        
    Returns:
        plaintext: 明文消息
    """
    # 1. 解析消息
    msg = json.loads(message)
    sender_id = msg["sender_id"]
    message_number = msg["message_number"]
    
    # 2. 获取发送方的receiving chain
    receiving_chain = group_state["members"][sender_id]["receiving_chain"]
    expected_msg_num = receiving_chain["message_number"]
    
    # 3. 检查消息类型并派生消息密钥
    if message_number > expected_msg_num:
        # 乱序消息，预先生成跳跃密钥（Skip Ratchet算法）
        for i in range(expected_msg_num, message_number):
            if i not in receiving_chain["skip_keys"]:
                # 为每一条缺失的消息生成跳跃密钥
                skipped_key = hkdf(
                    ikm=receiving_chain["chain_key"],
                    salt=b"",
                    info=b"message-key",
                    length=32
                )
                receiving_chain["skip_keys"][i] = skipped_key
                
                # 推进链密钥
                next_chain_key = hkdf(
                    ikm=receiving_chain["chain_key"],
                    salt=b"",
                    info=b"chain-key",
                    length=32
                )
                receiving_chain["chain_key"] = next_chain_key
        
        # 使用目标message_number对应的跳跃密钥
        message_key = receiving_chain["skip_keys"][message_number]
        
        # 清理已使用的跳跃密钥
        del receiving_chain["skip_keys"][message_number]
        
    elif message_number == expected_msg_num:
        # 顺序消息，使用当前链密钥
        message_key = hkdf(
            ikm=receiving_chain["chain_key"],
            salt=b"",
            info=b"message-key",
            length=32
        )
        
        # 推进链密钥
        next_chain_key = hkdf(
            ikm=receiving_chain["chain_key"],
            salt=b"",
            info=b"chain-key",
            length=32
        )
        receiving_chain["chain_key"] = next_chain_key
        
    else:
        # 重复消息或过期消息，拒绝
        raise ValueError(f"Invalid message number: {message_number}, expected: {expected_msg_num}")
    
    # 4. 解密消息
    iv = base64.b64decode(msg["iv"])
    ciphertext = base64.b64decode(msg["ciphertext"])
    auth_tag = base64.b64decode(msg["auth_tag"])
    
    plaintext = decrypt_aes_gcm(
        key=message_key,
        iv=iv,
        ciphertext=ciphertext,
        auth_tag=auth_tag
    )
    
    # 5. 验证发送方签名
    sender_signature = base64.b64decode(msg["sender_signature"])
    expected_signature = hmac.new(
        key=message_key,
        msg=ciphertext,
        digestmod=hashlib.sha256
    ).digest()
    
    if not hmac.compare_digest(sender_signature, expected_signature):
        raise ValueError("Invalid sender signature")
    
    # 6. 更新receiving chain状态
    group_state["members"][sender_id]["receiving_chain"] = {
        "chain_key": receiving_chain["chain_key"],
        "message_number": receiving_chain["message_number"] + 1,
        "skip_keys": receiving_chain["skip_keys"]
    }
    
    return plaintext.decode()


def verify_group_message_signature(message: str, group_state: dict) -> bool:
    """
    验证群组消息签名
    
    Args:
        message: 群组消息（JSON字符串）
        group_state: 群组状态
        
    Returns:
        valid: 是否有效
    """
    # 1. 解析消息
    msg = json.loads(message)
    sender_id = msg["sender_id"]
    
    # 2. 获取发送方的receiving chain
    receiving_chain = group_state["members"][sender_id]["receiving_chain"]
    
    # 3. 派生消息密钥
    message_key = hkdf(
        ikm=receiving_chain["chain_key"],
        salt=b"",
        info=b"message-key",
        length=32
    )
    
    # 4. 验证签名
    ciphertext = base64.b64decode(msg["ciphertext"])
    sender_signature = base64.b64decode(msg["sender_signature"])
    
    expected_signature = hmac.new(
        key=message_key,
        msg=ciphertext,
        digestmod=hashlib.sha256
    ).digest()
    
    valid = hmac.compare_digest(sender_signature, expected_signature)
    
    return valid


# 群组配置
group_id = "group:abc123"
root_key = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF")

# 发送方链密钥
sending_chain_key = bytes.fromhex("112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00")
message_number = 123

# 明文消息
plaintext = "Hello, Group SIP!"

# 随机nonce（固定用于测试）
iv = bytes.fromhex("000102030405060708090A0B0C")


# 1. 派生消息密钥
message_key = hkdf(
    ikm=sending_chain_key,
    salt=b"",
    info=b"message-key",
    length=32
)

# 2. 推进链密钥
next_chain_key = hkdf(
    ikm=sending_chain_key,
    salt=b"",
    info=b"chain-key",
    length=32
)

# 3. 加密消息
ciphertext, auth_tag = encrypt_aes_gcm(
    key=message_key,
    iv=iv,
    plaintext=plaintext.encode()
)

# 4. 发送方签名
sender_signature = hmac.new(
    key=message_key,
    msg=ciphertext,
    digestmod=hashlib.sha256
).digest()


# 注意：以下提供的十六进制值是示例值，用于演示测试向量的格式
# 要生成真实的测试向量，请使用提供的Python参考实现运行以下脚本

# 生成测试向量的Python脚本示例
import json
import base64
import hmac
import hashlib
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    kdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info)
    return kdf.derive(ikm)

def encrypt_aes_gcm(key: bytes, plaintext: bytes, iv: bytes) -> (bytes, bytes):
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return ciphertext[:len(plaintext)], ciphertext[len(plaintext):]

# 输入
sending_chain_key = bytes.fromhex("112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00")
plaintext = "Hello, Group SIP!".encode()
iv = bytes.fromhex("000102030405060708090A0B0C")

# 计算步骤
message_key = hkdf(sending_chain_key, b"", b"message-key", 32)
next_chain_key = hkdf(sending_chain_key, b"", b"chain-key", 32)
ciphertext, auth_tag = encrypt_aes_gcm(message_key, plaintext, iv)
sender_signature = hmac.new(message_key, ciphertext, hashlib.sha256).digest()

# 输出（真实值）
print(f"message_key: {message_key.hex().upper()}")
print(f"next_chain_key: {next_chain_key.hex().upper()}")
print(f"ciphertext: {ciphertext.hex().upper()}")
print(f"auth_tag: {auth_tag.hex().upper()}")
print(f"sender_signature: {sender_signature.hex().upper()}")


# 消息密钥（32 bytes）
message_key_expected = "[运行脚本生成的真实HKDF结果]"

# 推进的链密钥（32 bytes）
next_chain_key_expected = "[运行脚本生成的真实HKDF结果]"

# 密文（17 bytes，明文"Hello, Group SIP!"的AES-GCM加密结果）
ciphertext_expected = "[运行脚本生成的真实AES-GCM加密结果]"

# 认证标签（16 bytes，AES-GCM的认证标签）
auth_tag_expected = "[运行脚本生成的真实AES-GCM认证标签]"

# 发送方签名（32 bytes，HMAC-SHA256签名）
sender_signature_expected = "[运行脚本生成的真实HMAC-SHA256签名]"


import os
import time
import json
import base64
import hmac
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

# 常量
GROUP_PROTOCOL_VERSION = "SIP-1.0"
AES_GCM_NONCE_LENGTH = 12
MESSAGE_KEY_LENGTH = 32
CHAIN_KEY_LENGTH = 32

# HKDF派生
def hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF密钥派生"""
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return kdf.derive(ikm)

# AES-GCM加密
def encrypt_aes_gcm(key: bytes, plaintext: bytes, iv: bytes) -> (bytes, bytes):
    """AES-GCM加密"""
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return ciphertext[:len(plaintext)], ciphertext[len(plaintext):]

# AES-GCM解密
def decrypt_aes_gcm(key: bytes, ciphertext: bytes, iv: bytes, auth_tag: bytes) -> bytes:
    """AES-GCM解密"""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext + auth_tag, None)

# 发送群组消息
def send_group_message(plaintext: str, sending_chain: dict) -> (str, dict):
    """发送群组消息"""
    # 1. 派生消息密钥
    message_key = hkdf(
        ikm=sending_chain["chain_key"],
        salt=b"",
        info=b"message-key",
        length=MESSAGE_KEY_LENGTH
    )
    
    # 2. 推进链密钥
    next_chain_key = hkdf(
        ikm=sending_chain["chain_key"],
        salt=b"",
        info=b"chain-key",
        length=CHAIN_KEY_LENGTH
    )
    
    # 3. 加密消息
    iv = os.urandom(AES_GCM_NONCE_LENGTH)
    ciphertext, auth_tag = encrypt_aes_gcm(
        key=message_key,
        plaintext=plaintext.encode(),
        iv=iv
    )
    
    # 4. 发送方签名
    sender_signature = hmac.new(
        key=message_key,
        msg=ciphertext,
        digestmod=hashlib.sha256
    ).digest()
    
    # 5. 更新sending chain状态
    updated_sending_chain = {
        "chain_key": next_chain_key,
        "message_number": sending_chain["message_number"] + 1
    }
    
    # 6. 构建群组消息
    message = {
        "version": GROUP_PROTOCOL_VERSION,
        "type": "group_message",
        "timestamp": int(time.time() * 1000),
        "sender_id": "agent:decision-agent::session:abc",
        "group_id": "group:abc123",
        "message_number": sending_chain["message_number"],
        "iv": base64.b64encode(iv).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "auth_tag": base64.b64encode(auth_tag).decode(),
        "sender_signature": base64.b64encode(sender_signature).decode()
    }
    
    return json.dumps(message), updated_sending_chain

# 接收群组消息
def receive_group_message(message: str, receiving_chain: dict) -> (str, dict):
    """接收群组消息（完整版，支持乱序消息）"""
    # 1. 解析消息
    msg = json.loads(message)
    message_number = msg["message_number"]
    expected_msg_num = receiving_chain["message_number"]
    
    # 2. 检查消息类型并派生消息密钥
    if message_number > expected_msg_num:
        # 乱序消息，预先生成跳跃密钥（Skip Ratchet算法）
        for i in range(expected_msg_num, message_number):
            if i not in receiving_chain["skip_keys"]:
                # 为每一条缺失的消息生成跳跃密钥
                skipped_key = hkdf(
                    ikm=receiving_chain["chain_key"],
                    salt=b"",
                    info=b"message-key",
                    length=MESSAGE_KEY_LENGTH
                )
                receiving_chain["skip_keys"][i] = skipped_key
                
                # 推进链密钥
                next_chain_key = hkdf(
                    ikm=receiving_chain["chain_key"],
                    salt=b"",
                    info=b"chain-key",
                    length=CHAIN_KEY_LENGTH
                )
                receiving_chain["chain_key"] = next_chain_key
        
        # 使用目标message_number对应的跳跃密钥
        message_key = receiving_chain["skip_keys"][message_number]
        
        # 清理已使用的跳跃密钥
        del receiving_chain["skip_keys"][message_number]
        
    elif message_number == expected_msg_num:
        # 顺序消息，使用当前链密钥
        message_key = hkdf(
            ikm=receiving_chain["chain_key"],
            salt=b"",
            info=b"message-key",
            length=MESSAGE_KEY_LENGTH
        )
        
        # 推进链密钥
        next_chain_key = hkdf(
            ikm=receiving_chain["chain_key"],
            salt=b"",
            info=b"chain-key",
            length=CHAIN_KEY_LENGTH
        )
        receiving_chain["chain_key"] = next_chain_key
        
    else:
        # 重复消息或过期消息，拒绝
        raise ValueError(f"Invalid message number: {message_number}, expected: {expected_msg_num}")
    
    # 3. 解密消息
    iv = base64.b64decode(msg["iv"])
    ciphertext = base64.b64decode(msg["ciphertext"])
    auth_tag = base64.b64decode(msg["auth_tag"])
    
    plaintext = decrypt_aes_gcm(
        key=message_key,
        ciphertext=ciphertext,
        iv=iv,
        auth_tag=auth_tag
    )
    
    # 4. 验证发送方签名
    sender_signature = base64.b64decode(msg["sender_signature"])
    expected_signature = hmac.new(
        key=message_key,
        msg=ciphertext,
        digestmod=hashlib.sha256
    ).digest()
    
    if not hmac.compare_digest(sender_signature, expected_signature):
        raise ValueError("Invalid sender signature")
    
    # 5. 更新receiving chain状态
    updated_receiving_chain = {
        "chain_key": receiving_chain["chain_key"],
        "message_number": receiving_chain["message_number"] + 1,
        "skip_keys": receiving_chain["skip_keys"]
    }
    
    return plaintext.decode(), updated_receiving_chain

# 初始化群组链密钥
def initialize_group_chains(members: list, root_key: bytes) -> dict:
    """初始化群组链密钥"""
    chains = {}
    
    for member in members:
        # 派生sending chain key
        sending_chain_key = hkdf(
            ikm=root_key,
            salt=f"{member}:sending".encode(),
            info=b"sending-chain",
            length=CHAIN_KEY_LENGTH
        )
        
        # 派生receiving chain key
        receiving_chain_key = hkdf(
            ikm=root_key,
            salt=f"{member}:receiving".encode(),
            info=b"receiving-chain",
            length=CHAIN_KEY_LENGTH
        )
        
        chains[member] = {
            "sending_chain": {
                "chain_key": sending_chain_key,
                "message_number": 0
            },
            "receiving_chain": {
                "chain_key": receiving_chain_key,
                "message_number": 0,
                "skip_keys": {}
            }
        }
    
    return chains
