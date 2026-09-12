"""国密原语层测试 —— SM2/SM3/SM4 交叉验证与标准已知答案（ADR-001）

验证策略：
1. 标准已知答案（KAT）：SM3（GM/T 0004）、SM4（GM/T 0002 标准向量）
2. 独立实现交叉验证：SM2 点乘/ECDH 与 gmssl（纯 Python 第三方实现）双向一致；
   SM3 与 gmssl 一致
3. 构造正确性：HMAC-SM3 与 RFC 2104 手工构造一致；HKDF-SM3 与互操作参考实现
   的手工 RFC 5869 实现一致
4. 负路径：无效曲线点/错误长度/篡改密文均拒绝
"""

import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from sip_protocol.crypto.dh import (
    dh_exchange,
    generate_keypair,
    parse_public_key,
    serialize_private_key,
    serialize_public_key,
)
from sip_protocol.crypto.hkdf import derive_keys_triple_dh, hkdf
from sip_protocol.crypto.sm2 import SM2PrivateKey, SM2PublicKey, _on_curve
from sip_protocol.crypto.sm3 import SM3Hash, hmac_sm3, sm3_hash
from sip_protocol.crypto.sm4_gcm import decrypt_sm4_gcm, encrypt_sm4_gcm
from sip_protocol.crypto.suite import (
    AEAD_KEY_LENGTH,
    SUITE_EN,
    SUITE_ZH,
    digestmod,
    validate_suite,
)
from sip_protocol.crypto.xchacha20_poly1305 import (
    decrypt_xchacha20_poly1305,
    encrypt_xchacha20_poly1305,
)
from sip_protocol.exceptions import SuiteNegotiationError

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "interop"))

gmssl_sm2 = pytest.importorskip("gmssl.sm2", reason="gmssl dev 依赖缺失")
gmssl_sm3 = pytest.importorskip("gmssl.sm3", reason="gmssl dev 依赖缺失")
gmssl_func = pytest.importorskip("gmssl.func", reason="gmssl dev 依赖缺失")


class TestSM3:
    """SM3 杂凑：标准 KAT + gmssl 独立实现交叉验证"""

    # 双实现一致认定的标准值（OpenSSL SM3 与 gmssl SM3 独立复算一致）
    @pytest.mark.parametrize(
        "data,expected",
        [
            (b"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"),
            (b"abcd" * 16, "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"),
        ],
    )
    def test_sm3_known_answer(self, data, expected):
        assert sm3_hash(data).hex() == expected

    @pytest.mark.parametrize("data", [b"", b"abc", b"x" * 1000, "中文摘要输入".encode()])
    def test_sm3_matches_gmssl(self, data):
        assert sm3_hash(data).hex() == gmssl_sm3.sm3_hash(gmssl_func.bytes_to_list(data))

    def test_hmac_sm3_matches_rfc2104_manual(self):
        """标准库 hmac（适配器）与 RFC 2104 手工构造一致"""
        key, msg = b"key", b"msg"
        k = key + b"\x00" * (64 - len(key))
        inner = sm3_hash(bytes(b ^ 0x36 for b in k) + msg)
        manual = sm3_hash(bytes(b ^ 0x5C for b in k) + inner)
        assert hmac_sm3(key, msg) == manual

    def test_sm3hash_adapter_incremental_and_copy(self):
        h = SM3Hash(b"ab")
        h.update(b"c")
        copy = h.copy()
        h.update(b"d")
        assert h.hexdigest() == sm3_hash(b"abcd").hex()
        assert copy.hexdigest() == sm3_hash(b"abc").hex()
        assert SM3Hash.block_size == 64 and SM3Hash.digest_size == 32


class TestSM4GCM:
    """SM4-GCM AEAD：块密码 KAT + 往返 + 篡改拒绝"""

    def test_sm4_block_cipher_standard_kat(self):
        """GM/T 0002 标准向量（SM4-ECB 单块）"""
        key = bytes.fromhex("0123456789abcdeffedcba9876543210")
        plaintext = bytes.fromhex("0123456789abcdeffedcba9876543210")
        encryptor = Cipher(algorithms.SM4(key), modes.ECB()).encryptor()
        ct = encryptor.update(plaintext) + encryptor.finalize()
        assert ct.hex() == "681edf34d206965e86b3e94f536e4246"

    def test_roundtrip_with_aad(self):
        key, nonce = bytes(16), bytes(12)
        ct, tag = encrypt_sm4_gcm(key, "国密数据".encode(), nonce, b"aad-chain")
        assert len(tag) == 16
        assert decrypt_sm4_gcm(key, ct, nonce, tag, b"aad-chain") == "国密数据".encode()

    def test_tampered_ciphertext_rejected(self):
        key, nonce = bytes(16), bytes(12)
        ct, tag = encrypt_sm4_gcm(key, b"payload", nonce, None)
        with pytest.raises(InvalidTag):
            decrypt_sm4_gcm(key, bytes([ct[0] ^ 0xFF]) + ct[1:], nonce, tag, None)

    def test_wrong_aad_rejected(self):
        key, nonce = bytes(16), bytes(12)
        ct, tag = encrypt_sm4_gcm(key, b"payload", nonce, b"right")
        with pytest.raises(InvalidTag):
            decrypt_sm4_gcm(key, ct, nonce, tag, b"wrong")

    def test_dispatch_via_aead_module(self):
        """xchacha20_poly1305 模块的 suite 分派（SPEC §3 偏差 D1 模块双承载）"""
        key, nonce = bytes(16), bytes(12)
        ct, tag = encrypt_xchacha20_poly1305(key, b"via-dispatch", nonce, None, SUITE_ZH)
        assert decrypt_xchacha20_poly1305(key, ct, nonce, tag, None, SUITE_ZH) == b"via-dispatch"


class TestSM2:
    """SM2 曲线运算：生成/ECDH + gmssl 独立实现交叉验证 + 负路径"""

    def test_keypair_on_curve_and_encoding(self):
        priv, pub = generate_keypair(SUITE_ZH)
        raw = serialize_public_key(pub)
        assert len(raw) == 65 and raw[0] == 0x04
        assert _on_curve(pub.point)
        assert parse_public_key(raw, SUITE_ZH).public_bytes() == raw
        assert len(serialize_private_key(priv)) == 32

    def test_ecdh_symmetric(self):
        priv_a, pub_a = generate_keypair(SUITE_ZH)
        priv_b, pub_b = generate_keypair(SUITE_ZH)
        assert dh_exchange(priv_a, pub_b) == dh_exchange(priv_b, pub_a)
        assert len(dh_exchange(priv_a, pub_b)) == 32

    def test_public_key_derivation_matches_gmssl(self):
        priv, pub = generate_keypair(SUITE_ZH)
        d_hex = serialize_private_key(priv).hex()
        gm = gmssl_sm2.CryptSM2(private_key=d_hex, public_key="")
        g_hex = ("32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7"
                 "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0")
        assert gm._kg(int(d_hex, 16), g_hex) == serialize_public_key(pub).hex()[2:]

    def test_ecdh_matches_gmssl(self):
        priv_a, pub_a = generate_keypair(SUITE_ZH)
        priv_b, pub_b = generate_keypair(SUITE_ZH)
        d_b = serialize_private_key(priv_b).hex()
        pub_a_hex = serialize_public_key(pub_a).hex()[2:]
        gm = gmssl_sm2.CryptSM2(private_key=d_b, public_key=pub_a_hex)
        # gmssl 点乘的 x 坐标 == 我们的 ECDH 共享秘密
        assert gm._kg(int(d_b, 16), pub_a_hex)[:64] == dh_exchange(priv_b, pub_a).hex()
        assert dh_exchange(priv_a, pub_b) == dh_exchange(priv_b, pub_a)

    def test_rejects_off_curve_point(self):
        # 取合法点后扰动 y（不在曲线上）——构造即校验拒绝
        _, pub = generate_keypair(SUITE_ZH)
        x, y = pub.point
        bad_bytes = b"\x04" + x.to_bytes(32, "big") + ((y + 1) % (2**256)).to_bytes(32, "big")
        with pytest.raises(ValueError, match="不在推荐曲线上"):
            SM2PublicKey.from_public_bytes(bad_bytes)

    def test_rejects_malformed_encoding(self):
        with pytest.raises(ValueError):
            SM2PublicKey.from_public_bytes(bytes(64))  # 长度错误
        with pytest.raises(ValueError):
            SM2PublicKey.from_public_bytes(b"\x05" + bytes(64))  # 前缀错误

    def test_parse_public_key_length_guard(self):
        _, pub = generate_keypair(SUITE_ZH)
        with pytest.raises(SuiteNegotiationError):
            parse_public_key(serialize_public_key(pub), SUITE_EN)  # 65B 当 32B 解析
        priv, pub_en = generate_keypair(SUITE_EN)
        with pytest.raises(SuiteNegotiationError):
            parse_public_key(serialize_public_key(pub_en), SUITE_ZH)
        _ = priv  # 保持引用清晰

    def test_exchange_rejects_wrong_key_type(self):
        priv_zh, _pub = generate_keypair(SUITE_ZH)
        _priv_en, pub_en = generate_keypair(SUITE_EN)
        with pytest.raises(ValueError, match="SM2PublicKey"):
            priv_zh.exchange(pub_en)


class TestSuiteDispatch:
    """套件常量/校验/密钥长度语义（SPEC §3/§5）"""

    def test_validate_suite(self):
        assert validate_suite(SUITE_EN) == "EN"
        assert validate_suite(SUITE_ZH) == "ZH"
        for bad in ("XX", "", "zh", "en", None):
            with pytest.raises(ValueError):
                validate_suite(bad)

    def test_digestmod_dispatch(self):
        import hashlib

        assert digestmod(SUITE_EN) is hashlib.sha256
        assert digestmod(SUITE_ZH) is SM3Hash

    def test_hkdf_sm3_matches_reference_impl(self):
        """主库 HKDF-SM3（cryptography 构造）与参考实现手工 RFC 5869 一致"""
        import reference_impl as ref

        ikm, salt, info = b"ikm-material" * 3, b"salt-esc", b"info-ctx"
        assert hkdf(ikm, salt, info, 80, SUITE_ZH) == ref.hkdf_sm3(ikm, salt, info, 80)
        assert hkdf(ikm, salt, info, 96, SUITE_EN) == ref.hkdf_sha256(ikm, salt, info, 96)

    def test_triple_dh_key_lengths(self):
        keys_en = derive_keys_triple_dh(b"a" * 32, b"b" * 32, b"c" * 32, b"k" * 32, b"n" * 16, b"m" * 16)
        assert tuple(len(k) for k in keys_en) == (32, 32, 32)
        keys_zh = derive_keys_triple_dh(
            b"a" * 32, b"b" * 32, b"c" * 32, b"k" * 32, b"n" * 16, b"m" * 16, SUITE_ZH
        )
        assert tuple(len(k) for k in keys_zh) == (16, 32, 32)
        assert AEAD_KEY_LENGTH == {SUITE_EN: 32, SUITE_ZH: 16}

    def test_suites_produce_distinct_keys(self):
        """同输入不同套件 → 密钥必不相同（SM3 ≠ SHA256）"""
        en = derive_keys_triple_dh(b"a" * 32, b"b" * 32, b"c" * 32, b"k" * 32, b"n" * 16, b"m" * 16)
        zh = derive_keys_triple_dh(
            b"a" * 32, b"b" * 32, b"c" * 32, b"k" * 32, b"n" * 16, b"m" * 16, SUITE_ZH
        )
        assert en[1] != zh[1]


class TestSuiteNegotiationError:
    """SIP-PROTO-005 注册与序列化（异常体系完整性）"""

    def test_code_and_valueerror_compat(self):
        err = SuiteNegotiationError(message="x")
        assert err.code == "SIP-PROTO-005"
        assert isinstance(err, ValueError)
        assert isinstance(err, Exception)

    def test_dict_roundtrip(self):
        err = SuiteNegotiationError(message="协商失败", details={"offered": "ZH"})
        restored = type(err).from_dict(err.to_dict())
        assert isinstance(restored, SuiteNegotiationError)
        assert restored.code == "SIP-PROTO-005"
        assert restored.message == "协商失败"
