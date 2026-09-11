"""SIP-1.0 参考实现 —— 独立第二实现（互操作验证用）

实现来源：docs/SPEC.md（SIP-1.0 协议规范 v1.0）。
本模块 **不 import sip_protocol**——密钥调度、HMAC transcript、消息格式、
rekey 签名串、SIPFT 工件布局全部按规范条文从零实现，用于证明规范的
可 implement 性（完备性）：若仅凭规范无法复现主库行为，即为规范 bug。

密码原语复用（非协议逻辑）：cryptography 的 X25519 / ChaCha20-Poly1305、
argon2-cffi 的 Argon2id。HKDF-SHA256 由本模块按 RFC 5869 自行实现，
以使密钥调度完全独立于主库依赖路径。

用法：
    from reference_impl import ReferenceSIP            # 协议函数
    from reference_impl import ReferenceSession        # 有状态会话（消息收发）
    from reference_impl import pack_artifact, unpack_artifact   # SIPFT1.0
"""

from __future__ import annotations

import base64
import hmac
import hashlib
import json
import os
import struct
import time

from argon2 import low_level
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ─────────────────── 规范常量（SPEC §3/§4/§5/§7/§9） ───────────────────

PROTOCOL_VERSION = "SIP-1.0"
HANDSHAKE_NONCE_LENGTH = 16
REKEY_NONCE_LENGTH = 16
AEAD_NONCE_LENGTH = 12
TAG_LENGTH = 16
TIMESTAMP_TOLERANCE_MS = 300_000

KDF_SALT_HANDSHAKE = b"SIPHandshake"
KDF_INFO_HANDSHAKE = b"session-keys"
KDF_SALT_REKEY = b"SIPRekey"
KDF_INFO_REKEY = b"SIP-rekey"
ARGON2_SALT = b"SIPProtocolTestSalt"
ARGON2_PARAMS = dict(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32)

SIPFT_MAGIC = b"SIPFT1.0"
SIPFT_KDF_SALT = b"SIP-FileTransfer"


# ─────────────────── 原语层 ───────────────────


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256（RFC 5869 extract-then-expand），独立实现（SPEC §3）"""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def argon2id_psk(psk: bytes) -> bytes:
    """PSK 哈希：Argon2id 固定参数 + 固定盐（SPEC §3 / 偏差 D2）"""
    return low_level.hash_secret_raw(
        secret=psk, salt=ARGON2_SALT, type=low_level.Type.ID, **ARGON2_PARAMS
    )


def x25519_dh(priv_bytes: bytes, peer_pub_bytes: bytes) -> bytes:
    """X25519（原语复用）"""
    priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
    pub = x25519.X25519PublicKey.from_public_bytes(peer_pub_bytes)
    return priv.exchange(pub)


def generate_ephemeral() -> tuple[bytes, bytes]:
    """生成 X25519 临时密钥对，返回 (priv_raw32, pub_raw32)"""
    priv = x25519.X25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return priv_bytes, pub_bytes


def aead_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes | None) -> tuple[bytes, bytes]:
    """ChaCha20-Poly1305 加密 → (密文, 16 字节标签)（SPEC §3/§6.1）"""
    sealed = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    return sealed[: len(plaintext)], sealed[len(plaintext) :]


def aead_open(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes | None) -> bytes:
    """ChaCha20-Poly1305 解密；认证失败抛 InvalidTag"""
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext + tag, aad)


# ─────────────────── 握手（SPEC §4） ───────────────────


class ReferenceSIP:
    """无状态握手/密钥调度函数集"""

    # ---- 三重 DH 密钥调度（SPEC §4.3 / §5） ----

    @staticmethod
    def derive_session_keys(
        k1: bytes, k2: bytes, k3: bytes, psk: bytes, nonce_i: bytes, nonce_r: bytes
    ) -> dict[str, bytes]:
        """IKM = K1‖K2‖K3‖psk_hash‖N_i‖N_r（initiator 视角序）→ 三元组"""
        ikm = k1 + k2 + k3 + argon2id_psk(psk) + nonce_i + nonce_r
        okm = hkdf_sha256(ikm, KDF_SALT_HANDSHAKE, KDF_INFO_HANDSHAKE, 96)
        return {
            "encryption_key": okm[0:32],
            "auth_key": okm[32:64],
            "replay_key": okm[64:96],
        }

    # ---- transcript 签名（SPEC §4.4，字节级） ----

    @staticmethod
    def auth_transcript(ephemeral_pub_hex: str, nonce_hex: str, timestamp: int) -> bytes:
        """标准 json.dumps 分隔符（', ' 与 ': '）的 ASCII 逐字节复刻"""
        return (
            '{"ephemeral_pub": "'
            + ephemeral_pub_hex
            + '", "nonce": "'
            + nonce_hex
            + '", "timestamp": '
            + str(timestamp)
            + "}"
        ).encode()

    @staticmethod
    def complete_transcript() -> bytes:
        """Complete 回执覆盖串：json.dumps({"status": "verified"})"""
        return '{"status": "verified"}'.encode()

    # ---- 发起方 ----

    @staticmethod
    def initiator_start(
        psk: bytes,
        identity_priv: bytes | None = None,
        ephemeral_priv: bytes | None = None,
        nonce: bytes | None = None,
    ) -> tuple[dict, dict]:
        """生成 Hello。返回 (hello, initiator_state)"""
        id_priv, id_pub = (
            generate_ephemeral() if identity_priv is None else (identity_priv, _pub_of(identity_priv))
        )
        eph_priv, eph_pub = (
            generate_ephemeral() if ephemeral_priv is None else (ephemeral_priv, _pub_of(ephemeral_priv))
        )
        n_i = nonce or os.urandom(HANDSHAKE_NONCE_LENGTH)
        hello = {
            "version": PROTOCOL_VERSION,
            "type": "handshake",
            "step": "hello",
            "timestamp": int(time.time() * 1000),
            "identity_pub": id_pub.hex(),
            "ephemeral_pub": eph_pub.hex(),
            "nonce": n_i.hex(),
        }
        state = {
            "psk": psk,
            "identity_priv": id_priv,
            "ephemeral_priv": eph_priv,
            "nonce": n_i,
        }
        return hello, state

    @staticmethod
    def initiator_finish(
        auth: dict, state: dict, check_timestamp: bool = True
    ) -> dict[str, bytes]:
        """处理 Auth：版本→时间戳→三重 DH→HMAC 验证（SPEC §4.5）→ 会话密钥"""
        if auth.get("version") != PROTOCOL_VERSION:
            raise ValueError(f"不支持的协议版本: {auth.get('version')}")
        if check_timestamp and abs(int(time.time() * 1000) - auth["timestamp"]) > TIMESTAMP_TOLERANCE_MS:
            raise ValueError("时间戳验证失败：消息过期")

        e_i = bytes.fromhex(auth["auth_data"]["ephemeral_pub"])
        n_r = bytes.fromhex(auth["auth_data"]["nonce"])

        # initiator 视角（SPEC §4.3）：K1=DH(I_i,E_r) K2=DH(E_i,I_r) K3=DH(E_i,E_r)
        k1 = x25519_dh(state["identity_priv"], e_i)
        k2 = x25519_dh(state["ephemeral_priv"], bytes.fromhex(auth["identity_pub"]))
        k3 = x25519_dh(state["ephemeral_priv"], e_i)
        keys = ReferenceSIP.derive_session_keys(k1, k2, k3, state["psk"], state["nonce"], n_r)

        expected = hmac.new(
            keys["auth_key"],
            ReferenceSIP.auth_transcript(
                auth["auth_data"]["ephemeral_pub"], auth["auth_data"]["nonce"], auth["timestamp"]
            ),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(base64.b64decode(auth["signature"]), expected):
            raise ValueError("HMAC签名验证失败")
        return keys

    # ---- 响应方 ----

    @staticmethod
    def responder_handle_hello(
        hello: dict,
        psk: bytes,
        identity_priv: bytes | None = None,
        ephemeral_priv: bytes | None = None,
        nonce: bytes | None = None,
        check_timestamp: bool = True,
    ) -> tuple[dict, dict[str, bytes]]:
        """处理 Hello → Auth。返回 (auth, session_keys)"""
        if hello.get("version") != PROTOCOL_VERSION:
            raise ValueError(f"不支持的协议版本: {hello.get('version')}")
        if check_timestamp and abs(int(time.time() * 1000) - hello["timestamp"]) > TIMESTAMP_TOLERANCE_MS:
            raise ValueError("时间戳验证失败：消息过期")

        e_i = bytes.fromhex(hello["ephemeral_pub"])
        n_i = bytes.fromhex(hello["nonce"])
        id_priv, id_pub = (
            generate_ephemeral() if identity_priv is None else (identity_priv, _pub_of(identity_priv))
        )
        eph_priv, eph_pub = (
            generate_ephemeral() if ephemeral_priv is None else (ephemeral_priv, _pub_of(ephemeral_priv))
        )
        n_r = nonce or os.urandom(HANDSHAKE_NONCE_LENGTH)

        # responder 视角换算到 initiator 视角序：K1=DH(I_i,E_r) K2=DH(E_i,I_r) K3=DH(E_i,E_r)
        k1 = x25519_dh(eph_priv, bytes.fromhex(hello["identity_pub"]))
        k2 = x25519_dh(id_priv, e_i)
        k3 = x25519_dh(eph_priv, e_i)
        keys = ReferenceSIP.derive_session_keys(k1, k2, k3, psk, n_i, n_r)

        timestamp = int(time.time() * 1000)
        signature = hmac.new(
            keys["auth_key"],
            ReferenceSIP.auth_transcript(eph_pub.hex(), n_r.hex(), timestamp),
            hashlib.sha256,
        ).digest()
        auth = {
            "version": PROTOCOL_VERSION,
            "type": "handshake",
            "step": "auth",
            "timestamp": timestamp,
            "identity_pub": id_pub.hex(),
            "auth_data": {"ephemeral_pub": eph_pub.hex(), "nonce": n_r.hex()},
            "signature": base64.b64encode(signature).decode(),
        }
        return auth, keys


# ─────────────────── 会话消息（SPEC §6） ───────────────────


class ReferenceSession:
    """有状态会话端点：加解密 + replay_tag + 单调计数器（§6.2 处理顺序）"""

    def __init__(self, keys: dict[str, bytes], agent_id: str):
        self.keys = keys
        self.agent_id = agent_id
        self.send_counter = 0
        self.recv_counter = 0

    @staticmethod
    def replay_tag(replay_key: bytes, sender_id: str, counter: int) -> str:
        """HMAC-SHA256(replay_key, "{sender_id}:{counter}") → hex（SPEC §6.1）"""
        return hmac.new(
            replay_key, f"{sender_id}:{counter}".encode(), hashlib.sha256
        ).digest().hex()

    def encrypt(self, plaintext: str, recipient_id: str, nonce: bytes | None = None) -> dict:
        """加密消息字典（wire 格式 §6.1；nonce 可注入用于确定性测试向量）"""
        self.send_counter += 1
        iv = nonce or os.urandom(AEAD_NONCE_LENGTH)
        ciphertext, tag = aead_seal(self.keys["encryption_key"], iv, plaintext.encode(), None)
        return {
            "version": PROTOCOL_VERSION,
            "type": "message",
            "timestamp": int(time.time() * 1000),
            "sender_id": self.agent_id,
            "recipient_id": recipient_id,
            "message_counter": self.send_counter,
            "iv": base64.b64encode(iv).decode(),
            "payload": base64.b64encode(ciphertext).decode(),
            "auth_tag": base64.b64encode(tag).decode(),
            "replay_tag": self.replay_tag(
                self.keys["replay_key"], self.agent_id, self.send_counter
            ),
        }

    def decrypt(self, message: dict) -> str:
        """按 §6.2 顺序接收：replay_tag 验证 → 计数器 → AEAD 解密"""
        if message.get("version") != PROTOCOL_VERSION:
            raise ValueError(f"不支持的协议版本: {message.get('version')}")

        replay_tag = message.get("replay_tag")
        if replay_tag is not None:
            expected = self.replay_tag(
                self.keys["replay_key"],
                message["sender_id"],
                message["message_counter"],
            )
            if not hmac.compare_digest(expected, replay_tag):
                raise ValueError("重放攻击检测：replay_tag验证失败")

        if message["message_counter"] <= self.recv_counter:
            raise ValueError(
                f"消息计数器异常：收到 {message['message_counter']}，期望 > {self.recv_counter}"
            )

        plaintext = aead_open(
            self.keys["encryption_key"],
            base64.b64decode(message["iv"]),
            base64.b64decode(message["payload"]),
            base64.b64decode(message["auth_tag"]),
            None,
        )
        self.recv_counter = message["message_counter"]
        return plaintext.decode()


# ─────────────────── Rekey（SPEC §7） ───────────────────


class ReferenceRekey:
    """rekey 发起方（响应方入口见 handle_rekey_request）"""

    def __init__(self, keys: dict[str, bytes]):
        self.keys = keys
        self.sequence = 0
        self._eph_priv: bytes | None = None
        self._nonce: bytes | None = None

    # 发起方
    def create_request(self, reason: str = "scheduled", key_lifetime: int = 3600) -> dict:
        eph_priv, eph_pub = generate_ephemeral()
        nonce = os.urandom(REKEY_NONCE_LENGTH)
        eph_b64 = base64.b64encode(eph_pub).decode()
        nonce_b64 = base64.b64encode(nonce).decode()
        signature = hmac.new(
            self.keys["auth_key"],
            f"{REKEY_NONCE_LENGTH}:{eph_b64}:{nonce_b64}:{reason}:{key_lifetime}".encode(),
            hashlib.sha256,
        ).digest()
        self._eph_priv, self._nonce = eph_priv, nonce
        used = self.sequence
        self.sequence += 1
        return {
            "version": PROTOCOL_VERSION,
            "type": "rekey",
            "step": "request",
            "timestamp": int(time.time() * 1000),
            "sequence": used,
            "request": {
                "ephemeral_pub": eph_b64,
                "nonce": nonce_b64,
                "reason": reason,
                "key_lifetime": key_lifetime,
            },
            "signature": base64.b64encode(signature).decode(),
        }

    def process_response(self, response: dict, check_timestamp: bool = True) -> dict[str, bytes]:
        if response.get("version") != PROTOCOL_VERSION:
            raise ValueError("Invalid rekey response")
        if check_timestamp and abs(int(time.time() * 1000) - response["timestamp"]) > TIMESTAMP_TOLERANCE_MS:
            raise ValueError("Invalid rekey response")
        if response["sequence"] != self.sequence - 1:
            raise ValueError("Invalid rekey response")
        eph_b64 = response["response"]["ephemeral_pub"]
        nonce_b64 = response["response"]["nonce"]
        expected = hmac.new(
            self.keys["auth_key"],
            f"{REKEY_NONCE_LENGTH}:{eph_b64}:{nonce_b64}".encode(),
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(base64.b64decode(response["signature"]), expected):
            raise ValueError("Invalid rekey response")

        peer_pub = base64.b64decode(eph_b64)
        shared = x25519_dh(self._eph_priv, peer_pub)
        # 请求方 nonce（自己，在前）在前、响应方 nonce 在后（SPEC §7.4）
        return derive_rekey_keys(shared, self.keys, self._nonce, base64.b64decode(nonce_b64))


def derive_rekey_keys(
    shared: bytes,
    old_keys: dict[str, bytes],
    nonce_req: bytes,
    nonce_resp: bytes,
) -> dict[str, bytes]:
    """新钥派生（SPEC §7.4）：IKM = shared ‖ 旧三元组 ‖ N_req ‖ N_resp"""
    ikm = (
        shared
        + old_keys["encryption_key"]
        + old_keys["auth_key"]
        + old_keys["replay_key"]
        + nonce_req
        + nonce_resp
    )
    okm = hkdf_sha256(ikm, KDF_SALT_REKEY, KDF_INFO_REKEY, 96)
    return {
        "encryption_key": okm[0:32],
        "auth_key": okm[32:64],
        "replay_key": okm[64:96],
    }


def handle_rekey_request(
    keys: dict[str, bytes],
    request: dict,
    seen_sequence: int = 0,
    ephemeral_priv: bytes | None = None,
    nonce: bytes | None = None,
    check_timestamp: bool = True,
) -> tuple[dict, dict[str, bytes]]:
    """响应方：验证请求 → 生成响应 + 新钥（SPEC §7.2-7.4）"""
    if request.get("version") != PROTOCOL_VERSION:
        raise ValueError("Invalid rekey request")
    if check_timestamp and abs(int(time.time() * 1000) - request["timestamp"]) > TIMESTAMP_TOLERANCE_MS:
        raise ValueError("Invalid rekey request")
    if seen_sequence > 0 and request["sequence"] <= seen_sequence:
        raise ValueError("Invalid rekey request")

    req = request["request"]
    expected = hmac.new(
        keys["auth_key"],
        f"{REKEY_NONCE_LENGTH}:{req['ephemeral_pub']}:{req['nonce']}"
        f":{req['reason']}:{req['key_lifetime']}".encode(),
        hashlib.sha256,
    ).digest()
    if not hmac.compare_digest(base64.b64decode(request["signature"]), expected):
        raise ValueError("Invalid rekey request")

    eph_priv, eph_pub = (
        generate_ephemeral() if ephemeral_priv is None else (ephemeral_priv, _pub_of(ephemeral_priv))
    )
    n_resp = nonce or os.urandom(REKEY_NONCE_LENGTH)
    shared = x25519_dh(eph_priv, base64.b64decode(req["ephemeral_pub"]))
    new_keys = derive_rekey_keys(shared, keys, base64.b64decode(req["nonce"]), n_resp)

    eph_b64 = base64.b64encode(eph_pub).decode()
    nonce_b64 = base64.b64encode(n_resp).decode()
    signature = hmac.new(
        keys["auth_key"],
        f"{REKEY_NONCE_LENGTH}:{eph_b64}:{nonce_b64}".encode(),
        hashlib.sha256,
    ).digest()
    response = {
        "version": PROTOCOL_VERSION,
        "type": "rekey",
        "step": "response",
        "timestamp": int(time.time() * 1000),
        "sequence": request["sequence"],
        "response": {"ephemeral_pub": eph_b64, "nonce": nonce_b64},
        "signature": base64.b64encode(signature).decode(),
    }
    return response, new_keys


# ─────────────────── SIPFT1.0 工件（SPEC §9） ───────────────────


def sipft_header_key(master_key: bytes) -> bytes:
    return hkdf_sha256(master_key, SIPFT_KDF_SALT, b"header", 32)


def sipft_chunk_key(master_key: bytes, file_id: bytes, index: int) -> bytes:
    return hkdf_sha256(master_key, file_id, b"chunk:%d" % index, 32)


def pack_artifact(
    plaintext: bytes,
    master_key: bytes,
    file_name: str = "vector.bin",
    chunk_size: int = 1024,
    file_id: bytes | None = None,
    nonces: list[bytes] | None = None,
    created_at: str = "2026-01-01T00:00:00+00:00",
) -> bytes:
    """打包为 SIPFT1.0 工件字节串（确定性：file_id/nonces 可注入）"""
    fid = file_id or os.urandom(16)
    total_chunks = 0 if not plaintext else (len(plaintext) + chunk_size - 1) // chunk_size
    header = json.dumps(
        {
            "format": 1,
            "file_id": fid.hex(),
            "file_name": file_name,
            "mime_type": "application/octet-stream",
            "total_size": len(plaintext),
            "chunk_size": chunk_size,
            "total_chunks": total_chunks,
            "created_at": created_at,
        },
        ensure_ascii=False,
    ).encode()

    h_nonce = (nonces[0] if nonces else os.urandom(12))
    h_ct, h_tag = aead_seal(sipft_header_key(master_key), h_nonce, header, SIPFT_MAGIC)

    out = bytearray()
    out += SIPFT_MAGIC + struct.pack(">I", len(h_ct))
    out += h_nonce + h_ct + h_tag

    prev_tag = h_tag
    for i in range(total_chunks):
        chunk = plaintext[i * chunk_size : (i + 1) * chunk_size]
        c_nonce = nonces[i + 1] if nonces and i + 1 < len(nonces) else os.urandom(12)
        aad = SIPFT_MAGIC + fid + struct.pack(">I", i) + prev_tag
        c_ct, c_tag = aead_seal(sipft_chunk_key(master_key, fid, i), c_nonce, chunk, aad)
        out += c_nonce + c_ct + c_tag
        prev_tag = c_tag
    return bytes(out)


def unpack_artifact(artifact: bytes, master_key: bytes) -> tuple[bytes, dict]:
    """校验并解包 SIPFT1.0 工件。任何认证失败抛 ValueError（fail-fast §9.6）"""
    pos = 0

    def take(n: int) -> bytes:
        nonlocal pos
        if pos + n > len(artifact):
            raise ValueError("工件截断")
        data = artifact[pos : pos + n]
        pos += n
        return data

    if take(8) != SIPFT_MAGIC:
        raise ValueError("魔数不符")
    (header_len,) = struct.unpack(">I", take(4))
    if header_len > 64 * 1024:
        raise ValueError("头部超长")
    h_nonce, h_ct, h_tag = take(12), take(header_len), take(16)
    try:
        header_plain = aead_open(sipft_header_key(master_key), h_nonce, h_ct, h_tag, SIPFT_MAGIC)
    except Exception as error:  # InvalidTag
        raise ValueError("头部认证失败") from error
    header = json.loads(header_plain.decode())
    if header.get("format") != 1:
        raise ValueError("不支持的工件格式版本")

    fid = bytes.fromhex(header["file_id"])
    if len(fid) != 16:
        raise ValueError("file_id 长度非法")

    out = bytearray()
    prev_tag = h_tag
    for index in range(header["total_chunks"]):
        full, last = divmod(header["total_size"], header["chunk_size"])
        expected_len = header["chunk_size"] if index < full else last
        c_nonce, c_ct, c_tag = take(12), take(expected_len), take(16)
        aad = SIPFT_MAGIC + fid + struct.pack(">I", index) + prev_tag
        try:
            chunk = aead_open(
                sipft_chunk_key(master_key, fid, index), c_nonce, c_ct, c_tag, aad
            )
        except Exception as error:
            raise ValueError(f"块 {index} 完整性校验失败") from error
        out += chunk
        prev_tag = c_tag

    if len(out) != header["total_size"]:
        raise ValueError("解出字节数与头部不符")
    if pos != len(artifact):
        raise ValueError("工件尾部有多余数据")
    return bytes(out), header


# ─────────────────── 辅助 ───────────────────


def _pub_of(priv_bytes: bytes) -> bytes:
    priv = x25519.X25519PrivateKey.from_private_bytes(priv_bytes)
    return priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
