"""gmcvt CLI 冒烟测试：三子命令正负路径 + GB/T 32905 参考向量 + RFC 5869 手工
复算等价 + 输入通道（--hex/--b64 互斥、--file/stdin、尾换行剥除、python -m 子进程）。

等价性策略：CLI 输出分别对齐库函数（sm3_hash/hmac_sm3/hkdf ZH 路径）与独立
复算（stdlib hmac 构造、RFC 5869 手工 extract+expand）——后者不依赖被测实现，
可捕获复用层的构造性偏差。
"""

from __future__ import annotations

import base64
import hmac as hmac_module
import io
import subprocess
import sys

import pytest

from sip_protocol.crypto.hkdf import hkdf
from sip_protocol.crypto.sm3 import SM3Hash, hmac_sm3, sm3_hash
from sip_protocol.crypto.suite import SUITE_ZH
from sip_protocol.tools.gmcvt import main

# --- GB/T 32905（与 GM/T 0004 同源）参考向量 -----------------------------------

# 附录 A 例 1：消息 "abc"
SM3_ABC = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
# 附录 A 例 2：512 比特消息（"abcd" × 16，64 字节）
SM3_512BIT = "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"
# 空消息（标准杂凑函数公开一致性值，亦由 gmssl 交叉认定）
SM3_EMPTY = "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"

MSG_512BIT = "abcd" * 16

# HMAC/HKDF 固定输入（确定性）
HMAC_KEY = bytes.fromhex("0b" * 32)
HMAC_MSG = b"gmcvt cli hmac vector"
IKM = "国密互通 IKM 向量"  # UTF-8 文本通道 + 非 ASCII 覆盖
SALT = bytes.fromhex("0123456789abcdeffedcba9876543210")
INFO = b"gmcvt-hkdf-info"


def _manual_hkdf_sm3(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 手工 extract+expand（SM3 作 PRF）——CLI 链路的独立复算。"""
    if not salt:
        salt = b"\x00" * 32  # RFC 5869：未提供盐 = HashLen 全零盐
    prk = hmac_module.new(salt, ikm, SM3Hash).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac_module.new(prk, block + info + bytes([counter]), SM3Hash).digest()
        okm += block
        counter += 1
    return okm[:length]


# --- sm3 ---------------------------------------------------------------------


class TestSm3Cli:
    def test_text_channel_abc(self, capsys):
        assert main(["sm3", "abc"]) == 0
        assert capsys.readouterr().out.strip() == SM3_ABC

    def test_hex_channel_abc(self, capsys):
        # --hex 下 616263 解码即 "abc"——与文本通道殊途同归
        assert main(["sm3", "616263", "--hex"]) == 0
        assert capsys.readouterr().out.strip() == SM3_ABC

    def test_512bit_standard_vector(self, capsys):
        assert main(["sm3", MSG_512BIT]) == 0
        assert capsys.readouterr().out.strip() == SM3_512BIT

    def test_empty_message_stdin(self, capsys, monkeypatch):
        # 空输入 = 空消息（合法摘要），与密文工具的拒收语义刻意不同
        monkeypatch.setattr("sys.stdin", io.StringIO(""))
        assert main(["sm3"]) == 0
        assert capsys.readouterr().out.strip() == SM3_EMPTY

    def test_empty_hex_explicit(self, capsys):
        assert main(["sm3", "", "--hex"]) == 0
        assert capsys.readouterr().out.strip() == SM3_EMPTY

    def test_utf8_text_channel(self, capsys):
        assert main(["sm3", "中文摘要输入"]) == 0
        assert capsys.readouterr().out.strip() == sm3_hash("中文摘要输入".encode()).hex()

    def test_stdin_single_trailing_newline_stripped(self, capsys, monkeypatch):
        monkeypatch.setattr("sys.stdin", io.StringIO("abc\n"))
        assert main(["sm3"]) == 0
        assert capsys.readouterr().out.strip() == SM3_ABC

    def test_stdin_crlf_stripped(self, capsys, monkeypatch):
        monkeypatch.setattr("sys.stdin", io.StringIO("abc\r\n"))
        assert main(["sm3"]) == 0
        assert capsys.readouterr().out.strip() == SM3_ABC

    def test_only_single_trailing_newline_stripped(self, capsys, monkeypatch):
        # 双换行只剥一个——第二个 \n 是消息内容
        monkeypatch.setattr("sys.stdin", io.StringIO("abc\n\n"))
        assert main(["sm3"]) == 0
        assert capsys.readouterr().out.strip() == sm3_hash(b"abc\n").hex()

    def test_hex_whitespace_and_prefix_tolerated(self, capsys):
        assert main(["sm3", "0X 61 62\n63", "--hex"]) == 0
        assert capsys.readouterr().out.strip() == SM3_ABC

    def test_b64_channel(self, capsys):
        encoded = base64.b64encode(b"abc").decode()
        assert main(["sm3", encoded, "--b64"]) == 0
        assert capsys.readouterr().out.strip() == SM3_ABC


# --- hmac-sm3 ----------------------------------------------------------------


class TestHmacSm3Cli:
    def test_matches_library(self, capsys):
        assert main(["hmac-sm3", "--key", HMAC_KEY.hex(), HMAC_MSG.decode()]) == 0
        assert capsys.readouterr().out.strip() == hmac_sm3(HMAC_KEY, HMAC_MSG).hex()

    def test_matches_stdlib_hmac_construction(self, capsys):
        # stdlib hmac.new + SM3Hash 适配器——RFC 2104 结构等价性（不经被测实现）
        assert main(["hmac-sm3", "--key", HMAC_KEY.hex(), HMAC_MSG.decode()]) == 0
        out = capsys.readouterr().out.strip()
        expected = hmac_module.new(HMAC_KEY, HMAC_MSG, SM3Hash).hexdigest()
        assert out == expected

    def test_key_0x_prefix_accepted(self, capsys):
        assert main(["hmac-sm3", "--key", "0x" + HMAC_KEY.hex(), "abc"]) == 0
        assert capsys.readouterr().out.strip() == hmac_sm3(HMAC_KEY, b"abc").hex()

    def test_key_longer_than_block_padded_path(self, capsys):
        # 长于 64 字节块长的密钥走先杂凑再填充路径（RFC 2104 §2）
        long_key = bytes(range(100))
        assert main(["hmac-sm3", "--key", long_key.hex(), "abc"]) == 0
        assert capsys.readouterr().out.strip() == hmac_sm3(long_key, b"abc").hex()

    def test_empty_key_and_message(self, capsys):
        assert main(["hmac-sm3", "--key", "", "", "--hex"]) == 0
        assert capsys.readouterr().out.strip() == hmac_module.new(b"", b"", SM3Hash).hexdigest()

    def test_message_hex_channel(self, capsys):
        assert main(["hmac-sm3", "--key", HMAC_KEY.hex(), HMAC_MSG.hex(), "--hex"]) == 0
        assert capsys.readouterr().out.strip() == hmac_sm3(HMAC_KEY, HMAC_MSG).hex()

    def test_message_b64url_channel(self, capsys):
        encoded = base64.urlsafe_b64encode(HMAC_MSG).decode().rstrip("=")
        assert main(["hmac-sm3", "--key", HMAC_KEY.hex(), encoded, "--b64"]) == 0
        assert capsys.readouterr().out.strip() == hmac_sm3(HMAC_KEY, HMAC_MSG).hex()

    def test_bad_key_hex_exit_2(self, capsys):
        assert main(["hmac-sm3", "--key", "zz", "abc"]) == 2
        assert "--key" in capsys.readouterr().err


# --- hkdf-sm3 ----------------------------------------------------------------


class TestHkdfSm3Cli:
    def test_defaults_match_library(self, capsys):
        assert main(["hkdf-sm3", IKM]) == 0
        # 缺省 salt/info 空、len 32——与线协议密钥调度同一 hkdf() ZH 路径
        assert capsys.readouterr().out.strip() == hkdf(IKM.encode(), b"", b"", 32, SUITE_ZH).hex()

    def test_default_salt_equals_rfc5869_zero_salt(self, capsys):
        # CLI 缺省空盐 == RFC 5869 未提供盐（全零盐）——手工复算独立佐证
        assert main(["hkdf-sm3", IKM]) == 0
        assert capsys.readouterr().out.strip() == _manual_hkdf_sm3(IKM.encode(), b"", b"", 32).hex()

    def test_explicit_params_match_manual_rfc5869(self, capsys):
        assert (
            main(["hkdf-sm3", "--salt", SALT.hex(), "--info", INFO.hex(), "--len", "80", IKM]) == 0
        )
        expected = _manual_hkdf_sm3(IKM.encode(), SALT, INFO, 80)
        assert capsys.readouterr().out.strip() == expected.hex()
        # 同输入对齐库实现（复用路径回归）
        assert expected == hkdf(IKM.encode(), SALT, INFO, 80, SUITE_ZH)

    def test_salt_info_0x_prefix(self, capsys):
        assert main(["hkdf-sm3", "--salt", "0x" + SALT.hex(), "--info", INFO.hex(), IKM]) == 0
        assert capsys.readouterr().out.strip() == hkdf(IKM.encode(), SALT, INFO, 32, SUITE_ZH).hex()

    def test_len_max_bound_ok(self, capsys):
        # 255×32=8160 恰为上界（最后一个完整块）
        assert main(["hkdf-sm3", "--len", "8160", IKM]) == 0
        assert (
            capsys.readouterr().out.strip() == _manual_hkdf_sm3(IKM.encode(), b"", b"", 8160).hex()
        )

    def test_len_over_bound_exit_2(self, capsys):
        assert main(["hkdf-sm3", "--len", "8161", IKM]) == 2
        assert "越界" in capsys.readouterr().err

    def test_len_zero_exit_2(self, capsys):
        assert main(["hkdf-sm3", "--len", "0", IKM]) == 2

    def test_ikm_hex_channel(self, capsys):
        ikm = bytes(range(48))
        assert main(["hkdf-sm3", "--hex", ikm.hex()]) == 0
        assert capsys.readouterr().out.strip() == hkdf(ikm, b"", b"", 32, SUITE_ZH).hex()

    def test_ikm_b64_channel(self, capsys):
        ikm = bytes(range(48))
        encoded = base64.b64encode(ikm).decode()
        assert main(["hkdf-sm3", "--b64", encoded]) == 0
        assert capsys.readouterr().out.strip() == hkdf(ikm, b"", b"", 32, SUITE_ZH).hex()

    def test_bad_salt_exit_2(self, capsys):
        assert main(["hkdf-sm3", "--salt", "zz", IKM]) == 2
        assert "--salt" in capsys.readouterr().err


# --- 输入通道（跨子命令） -------------------------------------------------------


class TestInputChannels:
    def test_file_text_channel_trailing_newline_stripped(self, capsys, tmp_path):
        src = tmp_path / "msg.txt"
        src.write_text("abc\n", encoding="utf-8")
        assert main(["sm3", "--file", str(src)]) == 0
        assert capsys.readouterr().out.strip() == SM3_ABC

    def test_file_hex_channel_multiline(self, capsys, tmp_path):
        src = tmp_path / "msg.hex"
        src.write_text("61\n62 63\n", encoding="utf-8")
        assert main(["sm3", "--hex", "--file", str(src)]) == 0
        assert capsys.readouterr().out.strip() == SM3_ABC

    def test_missing_file_exit_2(self, capsys):
        assert main(["sm3", "--file", "/nonexistent/gmcvt.txt"]) == 2
        assert "错误" in capsys.readouterr().err

    def test_hex_and_b64_mutually_exclusive(self):
        with pytest.raises(SystemExit) as exc:
            main(["sm3", "616263", "--hex", "--b64"])
        assert exc.value.code == 2  # argparse 互斥拦截，与输入错误同码

    def test_b64_invalid_exit_2(self, capsys):
        assert main(["sm3", "!!!not-base64!!!", "--b64"]) == 2
        assert "base64" in capsys.readouterr().err

    def test_b64_with_0x_prefix_exit_2(self, capsys):
        # 0x 前缀是 hex 通道约定——喂给 --b64 视为误用，定向报错
        assert main(["sm3", "0x" + base64.b64encode(b"abc").decode(), "--b64"]) == 2
        assert "0x" in capsys.readouterr().err

    def test_bad_hex_exit_2(self, capsys):
        assert main(["sm3", "zz", "--hex"]) == 2
        assert "hex" in capsys.readouterr().err


# --- python -m 子进程冒烟（用户真实通路） -------------------------------------


class TestModuleSubprocess:
    def test_sm3_via_python_m(self):
        proc = subprocess.run(
            [sys.executable, "-m", "sip_protocol.tools.gmcvt", "sm3", "abc"],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0
        assert proc.stdout.strip() == SM3_ABC

    def test_hkdf_via_python_m_and_pipe(self):
        # stdin 管道（echo 形态带尾换行）→ 剥除后参与计算
        proc = subprocess.run(
            [sys.executable, "-m", "sip_protocol.tools.gmcvt", "hkdf-sm3", "--len", "32"],
            input=IKM + "\n",
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0
        assert proc.stdout.strip() == hkdf(IKM.encode(), b"", b"", 32, SUITE_ZH).hex()
