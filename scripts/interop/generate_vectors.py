"""SIP 互操作测试向量生成 —— 主库侧导出（SPEC §14 验证链）

从主库真实函数捕获握手中间态/密钥/密文/tag，序列化为 JSON 测试向量：
`tests/vectors/sip_test_vectors.json`（EN）/ `sip_test_vectors_zh.json`（ZH）。
参考实现（scripts/interop/reference_impl.py）仅凭 SPEC 消费这些向量并独立
复算，双向断言见 tests/test_interop.py 与 tests/test_interop_zh.py。

确定性注入（仅生成期 monkeypatch，不触碰库源码）：
- 会话消息 nonce：固定 12 字节（patch protocol.message.generate_nonce）
- SIPFT 工件 file_id / 头部与分块 nonce：固定序列（patch packer 命名空间）

用法：
    python scripts/interop/generate_vectors.py [输出路径]           # EN（默认）
    python scripts/interop/generate_vectors.py --suite zh [输出路径] # 国密套件
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from sip_protocol import __version__
from sip_protocol.crypto.dh import serialize_private_key, serialize_public_key
from sip_protocol.crypto.suite import SUITE_EN, SUITE_ZH
from sip_protocol.filetransfer import packer
from sip_protocol.protocol import message as proto_message
from sip_protocol.protocol.handshake import (
    complete_handshake,
    initiate_handshake,
    respond_handshake,
)
from sip_protocol.protocol.message import decrypt_message, encrypt_message
from sip_protocol.protocol.rekey import RekeyManager

PSK = b"interop-vector-psk-2026"
SENDER = "agent:vector::initiator"
RECIPIENT = "agent:vector::responder"
MSG_PLAINTEXT = "SIP-1.0 interop test vector — 你好，Agent！ ✓"
MSG_NONCE = bytes(range(12))  # 000102...0b
REKEY_REASON = "scheduled"
FILE_PLAINTEXT = bytes(range(256)) * 6  # 1536 B → 2 块（chunk_size=1024）
FILE_CHUNK_SIZE = 1024
FILE_ID = bytes.fromhex("00112233445566778899aabbccddeeff")
FILE_NONCES = [bytes([0xA0 + i]) * 12 for i in range(3)]  # 头 + 块0 + 块1

DEFAULT_OUTPUT = Path(__file__).resolve().parents[2] / "tests" / "vectors" / "sip_test_vectors.json"
DEFAULT_OUTPUT_ZH = Path(__file__).resolve().parents[2] / "tests" / "vectors" / "sip_test_vectors_zh.json"


def build_vectors(suite: str = SUITE_EN) -> dict:
    """生成完整向量集（每次调用随机性被钉死到固定注入值，可重复消费）"""
    vectors: dict = {
        "spec": "SIP-1.0 SPEC v1.1",
        "suite": suite,
        "generated_by": f"sip-protocol v{__version__}",
        "psk_hex": PSK.hex(),
    }

    # ── 1. 握手：捕获双方私钥与消息，导出会话密钥期望值 ──
    hello, state_a = initiate_handshake(PSK, suite=suite)
    auth, state_b, keys_b = respond_handshake(hello, PSK, suite=suite)
    keys_a, _session_state = complete_handshake(auth, state_a)
    assert keys_a["encryption_key"] == keys_b["encryption_key"], "主库两侧密钥不一致"
    assert len(keys_a["encryption_key"]) == (16 if suite == SUITE_ZH else 32)

    vectors["handshake"] = {
        "initiator_identity_priv": serialize_private_key(state_a["identity_private_key"]).hex(),
        "initiator_ephemeral_priv": serialize_private_key(state_a["ephemeral_private_key"]).hex(),
        "responder_identity_priv": serialize_private_key(state_b["identity_private_key"]).hex(),
        "responder_ephemeral_priv": serialize_private_key(state_b["ephemeral_private_key"]).hex(),
        "hello": hello,
        "auth": auth,
        "expected_keys": {
            "encryption_key": keys_a["encryption_key"].hex(),
            "auth_key": keys_a["auth_key"].hex(),
            "replay_key": keys_a["replay_key"].hex(),
        },
        # Complete 回执（可选验证，SPEC §4.6）
        "complete": _session_state["handshake_complete"],
    }
    # 附 responder 公钥（也可从 auth 消息读，显式导出便于独立核对）
    vectors["handshake"]["responder_identity_pub"] = serialize_public_key(
        state_b["identity_public_key"]
    ).hex()

    # ── 2. 会话消息：固定 nonce 加密一条消息，记录 wire 字典 ──
    original_gen_nonce = proto_message.generate_nonce
    proto_message.generate_nonce = lambda: MSG_NONCE
    try:
        encrypted = encrypt_message(
            encryption_key=keys_a["encryption_key"],
            plaintext=MSG_PLAINTEXT,
            sender_id=SENDER,
            recipient_id=RECIPIENT,
            message_counter=1,
            replay_key=keys_a["replay_key"],
            suite=suite,
        )
        assert decrypt_message(keys_b["encryption_key"], encrypted) == MSG_PLAINTEXT
    finally:
        proto_message.generate_nonce = original_gen_nonce

    vectors["message"] = {
        "sender_id": SENDER,
        "recipient_id": RECIPIENT,
        "message_counter": 1,
        "plaintext": MSG_PLAINTEXT,
        "nonce_hex": MSG_NONCE.hex(),
        "encryption_key_hex": keys_a["encryption_key"].hex(),
        "replay_key_hex": keys_a["replay_key"].hex(),
        "encrypted": encrypted,
    }

    # ── 3. Rekey：捕获双方临时私钥 + 请求/响应 + 新钥期望值 ──
    old_keys = {
        "encryption_key": keys_a["encryption_key"],
        "auth_key": keys_a["auth_key"],
        "replay_key": keys_a["replay_key"],
    }
    state_with_suite = dict(old_keys, suite=suite)
    mgr_a = RekeyManager(dict(state_with_suite), is_initiator=True)
    request = mgr_a.create_rekey_request(reason=REKEY_REASON, key_lifetime=3600)
    # 发起方临时私钥须在 process_rekey_response 清理之前捕获
    req_eph_priv = serialize_private_key(mgr_a._temp_new_ephemeral_private_key).hex()
    req_nonce = mgr_a._temp_new_ephemeral_nonce

    mgr_b = RekeyManager(dict(state_with_suite), is_initiator=False)
    response = mgr_b.process_rekey_request(request)
    new_keys_b = mgr_b.temp_new_keys

    new_keys_a = mgr_a.process_rekey_response(response)
    assert new_keys_a["encryption_key"] == new_keys_b["encryption_key"], "rekey 两侧新钥不一致"

    vectors["rekey"] = {
        "request": request,
        "response": response,
        "request_ephemeral_priv": req_eph_priv,
        "request_nonce_hex": req_nonce.hex(),
        # 响应方临时私钥在 mgr_b 上未清理，可直接捕获
        "response_ephemeral_priv": serialize_private_key(mgr_b._temp_new_ephemeral_private_key).hex(),
        "response_nonce_hex": mgr_b._temp_new_ephemeral_nonce.hex(),
        "old_keys": {k: v.hex() for k, v in old_keys.items()},
        "expected_new_keys": {k: v.hex() for k, v in new_keys_a.items()},
    }

    # ── 4. SIPFT1.0 工件：固定 file_id/nonce 打包，导出工件字节 ──
    master_key = bytes(range(32))
    tmp_in = (DEFAULT_OUTPUT.parent if suite == SUITE_EN else DEFAULT_OUTPUT_ZH.parent) / "_vector_source.bin"
    tmp_in.parent.mkdir(parents=True, exist_ok=True)
    tmp_in.write_bytes(FILE_PLAINTEXT)

    original_new_file_id = packer.new_file_id
    original_gen_nonce = packer.generate_nonce
    nonce_iter = iter(FILE_NONCES)
    packer.new_file_id = lambda: FILE_ID
    packer.generate_nonce = lambda: next(nonce_iter)
    try:
        pack_result = packer.pack_file(
            str(tmp_in), master_key, chunk_size=FILE_CHUNK_SIZE, suite=suite
        )
        artifact_bytes = Path(pack_result.artifact_path).read_bytes()
    finally:
        packer.new_file_id = original_new_file_id
        packer.generate_nonce = original_gen_nonce
        for leftover in (tmp_in, Path(pack_result.artifact_path)):
            leftover.unlink(missing_ok=True)

    vectors["filetransfer"] = {
        "master_key_hex": master_key.hex(),
        "file_name": tmp_in.name,
        "chunk_size": FILE_CHUNK_SIZE,
        "plaintext_hex": FILE_PLAINTEXT.hex(),
        "artifact_hex": artifact_bytes.hex(),
    }

    return vectors


def build_vectors_zh() -> dict:
    """ZH（国密）套件向量集——与 EN 同构流程，密钥/密文全走 SM2/SM3/SM4-GCM"""
    return build_vectors(SUITE_ZH)


def main() -> None:
    parser = argparse.ArgumentParser(description="SIP 互操作测试向量生成")
    parser.add_argument("output", nargs="?", type=Path, default=None, help="输出路径")
    parser.add_argument(
        "--suite", choices=["en", "zh"], default="en", help="密码套件（默认 en=国际套件）"
    )
    args = parser.parse_args()

    if args.suite == "zh":
        output = args.output or DEFAULT_OUTPUT_ZH
        vectors = build_vectors_zh()
    else:
        output = args.output or DEFAULT_OUTPUT
        vectors = build_vectors(SUITE_EN)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(vectors, indent=2, ensure_ascii=False) + "\n")
    print(f"向量已写入 {output}（suite={args.suite}，handshake/message/rekey/filetransfer 四组）")


if __name__ == "__main__":
    main()
