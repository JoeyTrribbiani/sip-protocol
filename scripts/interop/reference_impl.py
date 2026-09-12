"""SIP-1.0 参考实现 —— 独立第二实现（互操作验证用）

实现来源：docs/SPEC.md（SIP-1.0 协议规范 v1.1）。
本模块 **不 import sip_protocol**——密钥调度、HMAC transcript、消息格式、
rekey 签名串、SIPFT 工件布局全部按规范条文从零实现，用于证明规范的
可 implement 性（完备性）：若仅凭规范无法复现主库行为，即为规范 bug。

密码原语复用（非协议逻辑）：cryptography 的 X25519 / ChaCha20-Poly1305，
ZH 套件复用 cryptography 的 SM3 / SM4-GCM（与 EN 复用 ChaCha20 同构）；
argon2-cffi 的 Argon2id。HKDF（SHA256 与 SM3 两种 PRF）由本模块按
RFC 5869 自行实现，HMAC-SM3 按 RFC 2104 手工构造，SM2 曲线运算
（Jacobian 坐标）独立编写——与主库的（仿射坐标/标准库 hmac/cryptography HKDF）
构成独立第二实现。

用法：
    from reference_impl import ReferenceSIP            # 协议函数（suite="EN"|"ZH"）
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
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ─────────────────── 规范常量（SPEC §3/§4/§5/§7/§9） ───────────────────

PROTOCOL_VERSION = "SIP-1.0"
HANDSHAKE_NONCE_LENGTH = 16
REKEY_NONCE_LENGTH = 16
AEAD_NONCE_LENGTH = 12
TAG_LENGTH = 16
TIMESTAMP_TOLERANCE_MS = 300_000

SUITE_EN = "EN"
SUITE_ZH = "ZH"
SUPPORTED_SUITES = (SUITE_EN, SUITE_ZH)

KDF_SALT_HANDSHAKE = b"SIPHandshake"
KDF_INFO_HANDSHAKE = b"session-keys"
KDF_SALT_REKEY = b"SIPRekey"
KDF_INFO_REKEY = b"SIP-rekey"
ARGON2_SALT = b"SIPProtocolTestSalt"
ARGON2_PARAMS = dict(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32)

SIPFT_MAGIC = b"SIPFT1.0"
SIPFT_KDF_SALT = b"SIP-FileTransfer"

# ─────────────────── 原语层（EN：复用 cryptography） ───────────────────


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
    """PSK 哈希：Argon2id 固定参数 + 固定盐（SPEC §3 / 偏差 D2，套件无关）"""
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


def aead_seal(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes | None, suite: str = SUITE_EN
) -> tuple[bytes, bytes]:
    """AEAD 加密 → (密文, 16 字节标签)。EN → ChaCha20-Poly1305；ZH → SM4-GCM（SPEC §3/§6.1）"""
    if suite == SUITE_ZH:
        encryptor = Cipher(algorithms.SM4(key), modes.GCM(nonce)).encryptor()
        if aad is not None:
            encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, encryptor.tag
    sealed = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    return sealed[: len(plaintext)], sealed[len(plaintext) :]


def aead_open(
    key: bytes,
    nonce: bytes,
    ciphertext: bytes,
    tag: bytes,
    aad: bytes | None,
    suite: str = SUITE_EN,
) -> bytes:
    """AEAD 解密；认证失败抛 InvalidTag"""
    if suite == SUITE_ZH:
        decryptor = Cipher(algorithms.SM4(key), modes.GCM(nonce, tag)).decryptor()
        if aad is not None:
            decryptor.authenticate_additional_data(aad)
        return decryptor.update(ciphertext) + decryptor.finalize()
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext + tag, aad)


# ─────────────────── 原语层（ZH：SM3 / SM2 独立实现，SM4-GCM 复用） ───────────────────
#
# 与主库的独立性分工：SM3/HMAC-SM3/HKDF-SM3/SM2 点乘在本模块独立编写
# （HMAC 按 RFC 2104 手工构造、HKDF 按 RFC 5869 手工实现、SM2 用 Jacobian
# 坐标公式），SM4-GCM 块原语复用 cryptography（与 EN 复用 ChaCha20 同构）。

# GM/T 0003.5-2012 推荐曲线 sm2p256v1 参数
SM2_P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
SM2_A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
SM2_B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
SM2_N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
SM2_G = (
    0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
    0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0,
)
SM2_PUB_LENGTH = 65  # 非压缩 0x04 ‖ X ‖ Y


def _sm3(data: bytes) -> bytes:
    """SM3 杂凑（原语复用：cryptography/OpenSSL；与 gmssl 纯 Python 实现交叉验证）"""
    hashing = _hashes.Hash(_hashes.SM3())
    hashing.update(data)
    return hashing.finalize()


def hmac_digest(key: bytes, msg: bytes, suite: str) -> bytes:
    """套件分派的 HMAC：EN → HMAC-SHA256（标准库）；ZH → HMAC-SM3（RFC 2104 手工构造）"""
    if suite == SUITE_ZH:
        block = 64
        norm = key if len(key) <= block else _sm3(key)
        norm = norm + b"\x00" * (block - len(norm))
        inner = _sm3(bytes(b ^ 0x36 for b in norm) + msg)
        return _sm3(bytes(b ^ 0x5C for b in norm) + inner)
    return hmac.new(key, msg, hashlib.sha256).digest()


def hkdf_sm3(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SM3（RFC 5869 手工实现——与主库经 cryptography HKDF 构造独立）"""
    prk = hmac_digest(salt, ikm, SUITE_ZH)
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac_digest(prk, block + info + bytes([counter]), SUITE_ZH)
        okm += block
        counter += 1
    return okm[:length]


def hkdf_for_suite(ikm: bytes, salt: bytes, info: bytes, length: int, suite: str) -> bytes:
    """HKDF 分派（EN → SHA256；ZH → SM3）"""
    if suite == SUITE_ZH:
        return hkdf_sm3(ikm, salt, info, length)
    return hkdf_sha256(ikm, salt, info, length)


def _jac_double(
    point: tuple[int, int, int] | None,
) -> tuple[int, int, int] | None:
    """Jacobian 坐标倍点（X,Y,Z 表示仿射 (X/Z², Y/Z³)）"""
    if point is None:
        return None
    x1, y1, z1 = point
    if y1 == 0:
        return None
    yy = y1 * y1 % SM2_P
    s = 4 * x1 * yy % SM2_P
    m = (3 * x1 * x1 + SM2_A * pow(z1, 4, SM2_P)) % SM2_P
    x3 = (m * m - 2 * s) % SM2_P
    y3 = (m * (s - x3) - 8 * yy * yy) % SM2_P
    z3 = 2 * y1 * z1 % SM2_P
    return x3, y3, z3


def _jac_add(
    p: tuple[int, int, int] | None, q: tuple[int, int, int] | None
) -> tuple[int, int, int] | None:
    """Jacobian 坐标点加（add-1998-cmo 公式族）"""
    if p is None:
        return q
    if q is None:
        return p
    x1, y1, z1 = p
    x2, y2, z2 = q
    z1z1 = z1 * z1 % SM2_P
    z2z2 = z2 * z2 % SM2_P
    u1 = x1 * z2z2 % SM2_P
    u2 = x2 * z1z1 % SM2_P
    s1 = y1 * z2 * z2z2 % SM2_P
    s2 = y2 * z1 * z1z1 % SM2_P
    if u1 == u2:
        if s1 != s2:
            return None  # 互逆点
        return _jac_double(p)
    h = (u2 - u1) % SM2_P
    i = 4 * h * h % SM2_P
    j = h * i % SM2_P
    r = 2 * (s2 - s1) % SM2_P
    v = u1 * i % SM2_P
    x3 = (r * r - j - 2 * v) % SM2_P
    y3 = (r * (v - x3) - 2 * s1 * j) % SM2_P
    z3 = 2 * h * z1 * z2 % SM2_P
    return x3, y3, z3


def _jac_to_affine(point: tuple[int, int, int] | None) -> tuple[int, int] | None:
    """Jacobian → 仿射"""
    if point is None:
        return None
    x, y, z = point
    if z == 0:
        return None
    z_inv = pow(z, -1, SM2_P)
    return x * z_inv * z_inv % SM2_P, y * pow(z_inv, 3, SM2_P) % SM2_P


def _sm2_scalar_mult(k: int, affine: tuple[int, int]) -> tuple[int, int] | None:
    """MSB 优先 double-and-add（与主库 LSB 优先构成独立实现路径）"""
    result: tuple[int, int, int] | None = None
    addend: tuple[int, int, int] | None = (affine[0], affine[1], 1)
    for bit in bin(k)[2:]:
        result = _jac_double(result)
        if bit == "1":
            result = _jac_add(result, addend)
    return _jac_to_affine(result)


def _sm2_on_curve(point: tuple[int, int]) -> bool:
    x, y = point
    return (y * y - (x * x * x + SM2_A * x + SM2_B)) % SM2_P == 0


def generate_ephemeral_sm2() -> tuple[bytes, bytes]:
    """生成 SM2 临时密钥对，返回 (priv_raw32, pub_raw65)"""
    while True:
        scalar = int.from_bytes(os.urandom(32), "big")
        if 1 <= scalar < SM2_N:
            break
    pub = _sm2_scalar_mult(scalar, SM2_G)
    assert pub is not None
    return (
        scalar.to_bytes(32, "big"),
        b"\x04" + pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big"),
    )


def sm2_pub_of(priv_bytes: bytes) -> bytes:
    """SM2 私钥 → 65 字节公钥"""
    pub = _sm2_scalar_mult(int.from_bytes(priv_bytes, "big"), SM2_G)
    assert pub is not None
    return b"\x04" + pub[0].to_bytes(32, "big") + pub[1].to_bytes(32, "big")


def sm2_dh(priv_bytes: bytes, peer_pub65: bytes) -> bytes:
    """SM2 原始 ECDH：共享秘密 = [d]P 的 x 坐标（32 字节大端，SPEC §4.3）"""
    if len(peer_pub65) != SM2_PUB_LENGTH or peer_pub65[0] != 0x04:
        raise ValueError(f"SM2 公钥格式非法: {len(peer_pub65)} 字节")
    point = (
        int.from_bytes(peer_pub65[1:33], "big"),
        int.from_bytes(peer_pub65[33:65], "big"),
    )
    if not _sm2_on_curve(point):
        raise ValueError("SM2 公钥不在推荐曲线上")
    shared = _sm2_scalar_mult(int.from_bytes(priv_bytes, "big"), point)
    if shared is None:
        raise ValueError("SM2 ECDH 得到无穷远点")
    return shared[0].to_bytes(32, "big")


def dh_for_suite(priv_bytes: bytes, peer_pub: bytes, suite: str) -> bytes:
    """DH 分派：EN → X25519；ZH → SM2 ECDH"""
    if suite == SUITE_ZH:
        return sm2_dh(priv_bytes, peer_pub)
    return x25519_dh(priv_bytes, peer_pub)


def validate_suite(suite: str) -> str:
    """套件取值校验（SPEC §4.5：未知值拒绝）"""
    if suite not in SUPPORTED_SUITES:
        raise ValueError(f"未知的密码套件: {suite!r}（支持: EN, ZH）")
    return suite


def negotiate_suite(offered: str, local: str) -> str:
    """套件协商（SPEC §4.5）：单选语义，不匹配即拒绝（缺省 offered=EN 由调用方处理）"""
    if offered not in SUPPORTED_SUITES:
        raise ValueError(f"未知的密码套件: {offered!r}（支持: EN, ZH）")
    if offered != local:
        raise ValueError(f"密码套件协商失败: 对端要求 {offered}，本地配置 {local}（无降级回退）")
    return local


# ─────────────────── 握手（SPEC §4） ───────────────────


class ReferenceSIP:
    """无状态握手/密钥调度函数集（suite 经参数/状态携带，缺省 EN）"""

    # ---- 三重 DH 密钥调度（SPEC §4.3 / §5） ----

    @staticmethod
    def derive_session_keys(
        k1: bytes,
        k2: bytes,
        k3: bytes,
        psk: bytes,
        nonce_i: bytes,
        nonce_r: bytes,
        suite: str = SUITE_EN,
    ) -> dict[str, bytes]:
        """IKM = K1‖K2‖K3‖psk_hash‖N_i‖N_r（initiator 视角序）→ 三元组

        EN：HKDF-SHA256，OKM 96 → 3×32；ZH：HKDF-SM3，OKM 80 → 16+32+32（SPEC §5）"""
        validate_suite(suite)
        ikm = k1 + k2 + k3 + argon2id_psk(psk) + nonce_i + nonce_r
        if suite == SUITE_ZH:
            okm = hkdf_sm3(ikm, KDF_SALT_HANDSHAKE, KDF_INFO_HANDSHAKE, 80)
            return {
                "encryption_key": okm[0:16],
                "auth_key": okm[16:48],
                "replay_key": okm[48:80],
            }
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
        suite: str = SUITE_EN,
    ) -> tuple[dict, dict]:
        """生成 Hello。返回 (hello, initiator_state)"""
        validate_suite(suite)
        gen = generate_ephemeral_sm2 if suite == SUITE_ZH else generate_ephemeral

        def pub_of(priv: bytes) -> bytes:
            return sm2_pub_of(priv) if suite == SUITE_ZH else _pub_of(priv)

        id_priv, id_pub = gen() if identity_priv is None else (identity_priv, pub_of(identity_priv))
        eph_priv, eph_pub = (
            gen() if ephemeral_priv is None else (ephemeral_priv, pub_of(ephemeral_priv))
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
        if suite == SUITE_ZH:
            hello["suite"] = SUITE_ZH
        state = {
            "psk": psk,
            "identity_priv": id_priv,
            "ephemeral_priv": eph_priv,
            "nonce": n_i,
            "suite": suite,
        }
        return hello, state

    @staticmethod
    def initiator_finish(auth: dict, state: dict, check_timestamp: bool = True) -> dict[str, bytes]:
        """处理 Auth：版本→套件→时间戳→三重 DH→HMAC 验证（SPEC §4.5）→ 会话密钥"""
        suite = validate_suite(state.get("suite", SUITE_EN))
        if auth.get("version") != PROTOCOL_VERSION:
            raise ValueError(f"不支持的协议版本: {auth.get('version')}")
        negotiate_suite(auth.get("suite", SUITE_EN), suite)
        if (
            check_timestamp
            and abs(int(time.time() * 1000) - auth["timestamp"]) > TIMESTAMP_TOLERANCE_MS
        ):
            raise ValueError("时间戳验证失败：消息过期")

        e_i = bytes.fromhex(auth["auth_data"]["ephemeral_pub"])
        n_r = bytes.fromhex(auth["auth_data"]["nonce"])

        # initiator 视角（SPEC §4.3）：K1=DH(I_i,E_r) K2=DH(E_i,I_r) K3=DH(E_i,E_r)
        k1 = dh_for_suite(state["identity_priv"], e_i, suite)
        k2 = dh_for_suite(state["ephemeral_priv"], bytes.fromhex(auth["identity_pub"]), suite)
        k3 = dh_for_suite(state["ephemeral_priv"], e_i, suite)
        keys = ReferenceSIP.derive_session_keys(
            k1, k2, k3, state["psk"], state["nonce"], n_r, suite
        )

        expected = hmac_digest(
            keys["auth_key"],
            ReferenceSIP.auth_transcript(
                auth["auth_data"]["ephemeral_pub"], auth["auth_data"]["nonce"], auth["timestamp"]
            ),
            suite,
        )
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
        suite: str = SUITE_EN,
    ) -> tuple[dict, dict[str, bytes]]:
        """处理 Hello → Auth。返回 (auth, session_keys)"""
        validate_suite(suite)
        if hello.get("version") != PROTOCOL_VERSION:
            raise ValueError(f"不支持的协议版本: {hello.get('version')}")
        negotiate_suite(hello.get("suite", SUITE_EN), suite)
        if (
            check_timestamp
            and abs(int(time.time() * 1000) - hello["timestamp"]) > TIMESTAMP_TOLERANCE_MS
        ):
            raise ValueError("时间戳验证失败：消息过期")

        e_i = bytes.fromhex(hello["ephemeral_pub"])
        n_i = bytes.fromhex(hello["nonce"])
        gen = generate_ephemeral_sm2 if suite == SUITE_ZH else generate_ephemeral

        def pub_of(priv: bytes) -> bytes:
            return sm2_pub_of(priv) if suite == SUITE_ZH else _pub_of(priv)

        id_priv, id_pub = gen() if identity_priv is None else (identity_priv, pub_of(identity_priv))
        eph_priv, eph_pub = (
            gen() if ephemeral_priv is None else (ephemeral_priv, pub_of(ephemeral_priv))
        )
        n_r = nonce or os.urandom(HANDSHAKE_NONCE_LENGTH)

        # responder 视角换算到 initiator 视角序：K1=DH(I_i,E_r) K2=DH(E_i,I_r) K3=DH(E_i,E_r)
        k1 = dh_for_suite(eph_priv, bytes.fromhex(hello["identity_pub"]), suite)
        k2 = dh_for_suite(id_priv, e_i, suite)
        k3 = dh_for_suite(eph_priv, e_i, suite)
        keys = ReferenceSIP.derive_session_keys(k1, k2, k3, psk, n_i, n_r, suite)

        timestamp = int(time.time() * 1000)
        signature = hmac_digest(
            keys["auth_key"],
            ReferenceSIP.auth_transcript(eph_pub.hex(), n_r.hex(), timestamp),
            suite,
        )
        auth = {
            "version": PROTOCOL_VERSION,
            "type": "handshake",
            "step": "auth",
            "timestamp": timestamp,
            "identity_pub": id_pub.hex(),
            "auth_data": {"ephemeral_pub": eph_pub.hex(), "nonce": n_r.hex()},
            "signature": base64.b64encode(signature).decode(),
        }
        if suite == SUITE_ZH:
            auth["suite"] = SUITE_ZH
        return auth, keys


# ─────────────────── 会话消息（SPEC §6） ───────────────────


class ReferenceSession:
    """有状态会话端点：加解密 + replay_tag + 单调计数器（§6.2 处理顺序）"""

    def __init__(self, keys: dict[str, bytes], agent_id: str, suite: str = SUITE_EN):
        validate_suite(suite)
        self.keys = keys
        self.agent_id = agent_id
        self.suite = suite
        self.send_counter = 0
        self.recv_counter = 0

    @staticmethod
    def replay_tag(replay_key: bytes, sender_id: str, counter: int, suite: str = SUITE_EN) -> str:
        """HMAC(replay_key, "{sender_id}:{counter}") → hex（SPEC §6.1；摘要随套件分派）"""
        return hmac_digest(replay_key, f"{sender_id}:{counter}".encode(), suite).hex()

    def encrypt(self, plaintext: str, recipient_id: str, nonce: bytes | None = None) -> dict:
        """加密消息字典（wire 格式 §6.1；nonce 可注入用于确定性测试向量）"""
        self.send_counter += 1
        iv = nonce or os.urandom(AEAD_NONCE_LENGTH)
        ciphertext, tag = aead_seal(
            self.keys["encryption_key"], iv, plaintext.encode(), None, self.suite
        )
        message = {
            "version": PROTOCOL_VERSION,
            "type": "message",
            "timestamp": int(time.time() * 1000),
            "sender_id": self.agent_id,
            "recipient_id": recipient_id,
            "message_counter": self.send_counter,
            "iv": base64.b64encode(iv).decode(),
            "payload": base64.b64encode(ciphertext).decode(),
            "auth_tag": base64.b64encode(tag).decode(),
        }
        if self.suite != SUITE_EN:
            message["suite"] = self.suite
        message["replay_tag"] = self.replay_tag(
            self.keys["replay_key"], self.agent_id, self.send_counter, self.suite
        )
        return message

    def decrypt(self, message: dict) -> str:
        """按 §6.2 顺序接收：replay_tag 验证 → 计数器 → AEAD 解密（suite 自描述）"""
        if message.get("version") != PROTOCOL_VERSION:
            raise ValueError(f"不支持的协议版本: {message.get('version')}")
        suite = validate_suite(message.get("suite", SUITE_EN))

        replay_tag = message.get("replay_tag")
        if replay_tag is not None:
            expected = self.replay_tag(
                self.keys["replay_key"],
                message["sender_id"],
                message["message_counter"],
                suite,
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
            suite,
        )
        self.recv_counter = message["message_counter"]
        return plaintext.decode()


# ─────────────────── Rekey（SPEC §7） ───────────────────


class ReferenceRekey:
    """rekey 发起方（响应方入口见 handle_rekey_request）"""

    def __init__(self, keys: dict[str, bytes], suite: str = SUITE_EN):
        validate_suite(suite)
        self.keys = keys
        self.suite = suite
        self.sequence = 0
        self._eph_priv: bytes | None = None
        self._nonce: bytes | None = None

    # 发起方
    def create_request(self, reason: str = "scheduled", key_lifetime: int = 3600) -> dict:
        gen = generate_ephemeral_sm2 if self.suite == SUITE_ZH else generate_ephemeral
        eph_priv, eph_pub = gen()
        nonce = os.urandom(REKEY_NONCE_LENGTH)
        eph_b64 = base64.b64encode(eph_pub).decode()
        nonce_b64 = base64.b64encode(nonce).decode()
        signature = hmac_digest(
            self.keys["auth_key"],
            f"{REKEY_NONCE_LENGTH}:{eph_b64}:{nonce_b64}:{reason}:{key_lifetime}".encode(),
            self.suite,
        )
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
        if (
            check_timestamp
            and abs(int(time.time() * 1000) - response["timestamp"]) > TIMESTAMP_TOLERANCE_MS
        ):
            raise ValueError("Invalid rekey response")
        if response["sequence"] != self.sequence - 1:
            raise ValueError("Invalid rekey response")
        eph_b64 = response["response"]["ephemeral_pub"]
        nonce_b64 = response["response"]["nonce"]
        expected = hmac_digest(
            self.keys["auth_key"],
            f"{REKEY_NONCE_LENGTH}:{eph_b64}:{nonce_b64}".encode(),
            self.suite,
        )
        if not hmac.compare_digest(base64.b64decode(response["signature"]), expected):
            raise ValueError("Invalid rekey response")

        peer_pub = base64.b64decode(eph_b64)
        shared = dh_for_suite(self._eph_priv, peer_pub, self.suite)
        # 请求方 nonce（自己，在前）在前、响应方 nonce 在后（SPEC §7.4）
        return derive_rekey_keys(
            shared, self.keys, self._nonce, base64.b64decode(nonce_b64), self.suite
        )


def derive_rekey_keys(
    shared: bytes,
    old_keys: dict[str, bytes],
    nonce_req: bytes,
    nonce_resp: bytes,
    suite: str = SUITE_EN,
) -> dict[str, bytes]:
    """新钥派生（SPEC §7.4）：IKM = shared ‖ 旧三元组 ‖ N_req ‖ N_resp

    EN：OKM 96 → 3×32；ZH：OKM 80 → 16+32+32（SPEC §5）"""
    validate_suite(suite)
    ikm = (
        shared
        + old_keys["encryption_key"]
        + old_keys["auth_key"]
        + old_keys["replay_key"]
        + nonce_req
        + nonce_resp
    )
    if suite == SUITE_ZH:
        okm = hkdf_sm3(ikm, KDF_SALT_REKEY, KDF_INFO_REKEY, 80)
        return {
            "encryption_key": okm[0:16],
            "auth_key": okm[16:48],
            "replay_key": okm[48:80],
        }
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
    suite: str = SUITE_EN,
) -> tuple[dict, dict[str, bytes]]:
    """响应方：验证请求 → 生成响应 + 新钥（SPEC §7.2-7.4）"""
    validate_suite(suite)
    if request.get("version") != PROTOCOL_VERSION:
        raise ValueError("Invalid rekey request")
    if (
        check_timestamp
        and abs(int(time.time() * 1000) - request["timestamp"]) > TIMESTAMP_TOLERANCE_MS
    ):
        raise ValueError("Invalid rekey request")
    if seen_sequence > 0 and request["sequence"] <= seen_sequence:
        raise ValueError("Invalid rekey request")

    req = request["request"]
    expected = hmac_digest(
        keys["auth_key"],
        f"{REKEY_NONCE_LENGTH}:{req['ephemeral_pub']}:{req['nonce']}"
        f":{req['reason']}:{req['key_lifetime']}".encode(),
        suite,
    )
    if not hmac.compare_digest(base64.b64decode(request["signature"]), expected):
        raise ValueError("Invalid rekey request")

    gen = generate_ephemeral_sm2 if suite == SUITE_ZH else generate_ephemeral

    def pub_of(priv: bytes) -> bytes:
        return sm2_pub_of(priv) if suite == SUITE_ZH else _pub_of(priv)

    eph_priv, eph_pub = (
        gen() if ephemeral_priv is None else (ephemeral_priv, pub_of(ephemeral_priv))
    )
    n_resp = nonce or os.urandom(REKEY_NONCE_LENGTH)
    shared = dh_for_suite(eph_priv, base64.b64decode(req["ephemeral_pub"]), suite)
    new_keys = derive_rekey_keys(shared, keys, base64.b64decode(req["nonce"]), n_resp, suite)

    eph_b64 = base64.b64encode(eph_pub).decode()
    nonce_b64 = base64.b64encode(n_resp).decode()
    signature = hmac_digest(
        keys["auth_key"],
        f"{REKEY_NONCE_LENGTH}:{eph_b64}:{nonce_b64}".encode(),
        suite,
    )
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


def _sipft_key_length(suite: str) -> int:
    """AEAD 密钥长度：EN 32（ChaCha20）；ZH 16（SM4-128）"""
    return 16 if suite == SUITE_ZH else 32


def sipft_header_key(master_key: bytes, suite: str = SUITE_EN) -> bytes:
    return hkdf_for_suite(master_key, SIPFT_KDF_SALT, b"header", _sipft_key_length(suite), suite)


def sipft_chunk_key(master_key: bytes, file_id: bytes, index: int, suite: str = SUITE_EN) -> bytes:
    return hkdf_for_suite(master_key, file_id, b"chunk:%d" % index, _sipft_key_length(suite), suite)


def pack_artifact(
    plaintext: bytes,
    master_key: bytes,
    file_name: str = "vector.bin",
    chunk_size: int = 1024,
    file_id: bytes | None = None,
    nonces: list[bytes] | None = None,
    created_at: str = "2026-01-01T00:00:00+00:00",
    suite: str = SUITE_EN,
) -> bytes:
    """打包为 SIPFT1.0 工件字节串（确定性：file_id/nonces 可注入；suite 为带外约定）"""
    validate_suite(suite)
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

    h_nonce = nonces[0] if nonces else os.urandom(12)
    h_ct, h_tag = aead_seal(
        sipft_header_key(master_key, suite), h_nonce, header, SIPFT_MAGIC, suite
    )

    out = bytearray()
    out += SIPFT_MAGIC + struct.pack(">I", len(h_ct))
    out += h_nonce + h_ct + h_tag

    prev_tag = h_tag
    for i in range(total_chunks):
        chunk = plaintext[i * chunk_size : (i + 1) * chunk_size]
        c_nonce = nonces[i + 1] if nonces and i + 1 < len(nonces) else os.urandom(12)
        aad = SIPFT_MAGIC + fid + struct.pack(">I", i) + prev_tag
        c_ct, c_tag = aead_seal(
            sipft_chunk_key(master_key, fid, i, suite), c_nonce, chunk, aad, suite
        )
        out += c_nonce + c_ct + c_tag
        prev_tag = c_tag
    return bytes(out)


def unpack_artifact(
    artifact: bytes, master_key: bytes, suite: str = SUITE_EN
) -> tuple[bytes, dict]:
    """校验并解包 SIPFT1.0 工件。任何认证失败抛 ValueError（fail-fast §9.6）"""
    validate_suite(suite)
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
        header_plain = aead_open(
            sipft_header_key(master_key, suite), h_nonce, h_ct, h_tag, SIPFT_MAGIC, suite
        )
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
                sipft_chunk_key(master_key, fid, index, suite), c_nonce, c_ct, c_tag, aad, suite
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
