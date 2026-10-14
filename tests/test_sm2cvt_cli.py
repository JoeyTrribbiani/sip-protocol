"""sm2cvt CLI 冒烟测试：三子命令正负路径 + 文件/stdin 输入 + python -m 子进程。

密文向量为"真实曲线点"合成（C1 = [k]G 经 SM2PrivateKey 派生，KDF/C3 按
GM/T 0003.4/.5 公式手拼），不依赖 gmssl；另有 gmssl 真实密文交叉冒烟
（dev 依赖缺失则跳过）。
"""

from __future__ import annotations

import io
import subprocess
import sys

import pytest

from sip_protocol.crypto.sm2 import SM2PrivateKey, SM2PublicKey
from sip_protocol.crypto.sm3 import sm3_hash
from sip_protocol.tools.sm2cvt import main

try:  # gmssl 仅 dev 组依赖（交叉验证），缺失时跳过真实向量用例
    from gmssl import sm2 as gmssl_sm2

    GMSSL_AVAILABLE = True
except ImportError:
    GMSSL_AVAILABLE = False

# --- 固定向量（真实曲线点合成，确定性） ---------------------------------------

# 解密方私钥 d 与加密方临时私钥 k（均 [1, n) 内合法标量，d 与互通向量同款）
D_HEX = bytes(range(1, 33)).hex()
_K = bytes(range(0x21, 0x41))
_MSG = b"sip-sm2cvt cli vector"  # 21B（单 KDF 块内）

_priv = SM2PrivateKey.from_private_bytes(bytes.fromhex(D_HEX))
# C1 = [k]G（真实曲线点，64B x‖y）；共享点 = [d]C1 = [d][k]G
C1 = SM2PrivateKey.from_private_bytes(_K).public_key().public_bytes()[1:]
SHARED = _priv.exchange_point(SM2PublicKey.from_public_bytes(b"\x04" + C1))
# KDF(x2‖y2, klen) 单块展开（klen=21 < 32 截断）；C3 = Hash(x2‖M‖y2)
KEYSTREAM = sm3_hash(SHARED + (1).to_bytes(4, "big"))[: len(_MSG)]
C2 = bytes(a ^ b for a, b in zip(_MSG, KEYSTREAM))
C3 = sm3_hash(SHARED[:32] + _MSG + SHARED[32:])

CT_C1C2C3_HEX = (C1 + C2 + C3).hex()
CT_C1C3C2_HEX = (C1 + C3 + C2).hex()
CT_C1C3C2_04_HEX = (b"\x04" + C1 + C3 + C2).hex()


# --- detect -----------------------------------------------------------------


class TestDetectCli:
    def test_bare_prints_format(self, capsys):
        assert main(["detect", CT_C1C2C3_HEX]) == 0
        assert capsys.readouterr().out == "C1C2C3\n"

    def test_prefixed_prints_format(self, capsys):
        assert main(["detect", CT_C1C3C2_04_HEX]) == 0
        assert capsys.readouterr().out == "C1C2C3+04\n"

    def test_short_input_exit_2(self, capsys):
        assert main(["detect", "0410"]) == 2
        assert "错误" in capsys.readouterr().err


# --- convert ----------------------------------------------------------------


class TestConvertCli:
    def test_convert_order_swap(self, capsys):
        assert main(["convert", "--from", "C1C2C3", "--to", "C1C3C2", CT_C1C2C3_HEX]) == 0
        assert capsys.readouterr().out.strip() == CT_C1C3C2_HEX

    def test_convert_to_prefixed_roundtrip(self, capsys):
        assert main(["convert", "--from", "C1C2C3", "--to", "C1C3C2+04", CT_C1C2C3_HEX]) == 0
        out04 = capsys.readouterr().out.strip()
        assert out04 == CT_C1C3C2_04_HEX
        # 带前缀密文再转回无前缀旧序——双向无损
        assert main(["convert", "--from", "C1C3C2+04", "--to", "C1C2C3", out04]) == 0
        assert capsys.readouterr().out.strip() == CT_C1C2C3_HEX

    def test_convert_out_file(self, capsys, tmp_path):
        target = tmp_path / "out.hex"
        assert (
            main(
                ["convert", "--from", "C1C2C3", "--to", "C1C3C2", CT_C1C2C3_HEX, "--out", str(target)]
            )
            == 0
        )
        assert target.read_text(encoding="utf-8").strip() == CT_C1C3C2_HEX

    def test_convert_from_file_whitespace_and_prefix(self, tmp_path):
        # hex 文本文件：换行/空格/0x 前缀/大写混合，统一容忍
        chunked = "\n".join(CT_C1C2C3_HEX[i : i + 32].upper() for i in range(0, len(CT_C1C2C3_HEX), 32))
        src = tmp_path / "ct.hex"
        src.write_text("0X" + chunked + "\n", encoding="utf-8")
        assert main(["convert", "--from", "C1C2C3", "--to", "C1C3C2", "--file", str(src)]) == 0

    def test_convert_stdin(self, capsys, monkeypatch):
        monkeypatch.setattr("sys.stdin", io.StringIO(CT_C1C2C3_HEX + "\n"))
        assert main(["convert", "--from", "C1C2C3", "--to", "C1C3C2"]) == 0
        assert capsys.readouterr().out.strip() == CT_C1C3C2_HEX

    def test_convert_bad_hex_exit_2(self, capsys):
        assert main(["convert", "--from", "C1C2C3", "--to", "C1C3C2", "zz"]) == 2
        assert "错误" in capsys.readouterr().err

    def test_convert_empty_stdin_exit_2(self, capsys, monkeypatch):
        monkeypatch.setattr("sys.stdin", io.StringIO(""))
        assert main(["convert", "--from", "C1C2C3", "--to", "C1C3C2"]) == 2
        assert "输入为空" in capsys.readouterr().err

    def test_convert_prefix_claim_mismatch_exit_2(self, capsys):
        # 无前缀密文声明带 04 前缀格式——字节与声明不符
        assert main(["convert", "--from", "C1C2C3+04", "--to", "C1C3C2", CT_C1C2C3_HEX]) == 2

    def test_convert_unknown_format_rejected(self):
        with pytest.raises(SystemExit) as exc:
            main(["convert", "--from", "C2C1C3", "--to", "C1C3C2", CT_C1C2C3_HEX])
        assert exc.value.code == 2  # argparse choices 拦截，与输入错误同码

    def test_convert_missing_to_rejected(self):
        with pytest.raises(SystemExit) as exc:
            main(["convert", "--from", "C1C2C3", CT_C1C2C3_HEX])
        assert exc.value.code == 2


# --- verify -----------------------------------------------------------------


class TestVerifyCli:
    def test_correct_format_passes(self, capsys):
        assert main(["verify", "--fmt", "C1C2C3", "--privkey", D_HEX, CT_C1C2C3_HEX]) == 0
        assert "校验通过" in capsys.readouterr().out

    def test_wrong_order_fails_exit_1(self, capsys):
        # 旧序密文声明新序——正是静默错解场景，退出码 1 供脚本消费
        assert main(["verify", "--fmt", "C1C3C2", "--privkey", D_HEX, CT_C1C2C3_HEX]) == 1
        assert "校验失败" in capsys.readouterr().out

    def test_prefixed_format_passes(self, capsys):
        assert main(["verify", "--fmt", "C1C3C2+04", "--privkey", D_HEX, CT_C1C3C2_04_HEX]) == 0

    def test_tampered_c2_fails_exit_1(self, capsys):
        bad = bytearray(bytes.fromhex(CT_C1C2C3_HEX))
        bad[64] ^= 0x01
        assert main(["verify", "--fmt", "C1C2C3", "--privkey", D_HEX, bytes(bad).hex()]) == 1

    def test_tampered_c1_not_on_curve_exit_2(self, capsys):
        # C1 篡改后不在推荐曲线上——派生共享点前即被校验拦下
        bad = bytearray(bytes.fromhex(CT_C1C2C3_HEX))
        bad[0] ^= 0x01
        assert main(["verify", "--fmt", "C1C2C3", "--privkey", D_HEX, bytes(bad).hex()]) == 2
        assert "曲线" in capsys.readouterr().err

    def test_privkey_0x_prefix_accepted(self, capsys):
        assert main(["verify", "--fmt", "C1C2C3", "--privkey", "0x" + D_HEX, CT_C1C2C3_HEX]) == 0

    def test_privkey_bad_length_exit_2(self, capsys):
        assert main(["verify", "--fmt", "C1C2C3", "--privkey", "abcd", CT_C1C2C3_HEX]) == 2
        assert "私钥长度" in capsys.readouterr().err


# --- python -m 子进程冒烟（用户真实通路） -------------------------------------


class TestModuleSubprocess:
    def test_detect_via_python_m(self):
        proc = subprocess.run(
            [sys.executable, "-m", "sip_protocol.tools.sm2cvt", "detect", CT_C1C2C3_HEX],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0
        assert proc.stdout.strip() == "C1C2C3"

    def test_verify_wrong_order_exit_1_via_python_m(self):
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "sip_protocol.tools.sm2cvt",
                "verify",
                "--fmt",
                "C1C3C2",
                "--privkey",
                D_HEX,
                CT_C1C2C3_HEX,
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 1
        assert "校验失败" in proc.stdout


# --- gmssl 真实密文交叉冒烟（独立实现互认，dev 依赖缺失则跳过） ----------------


@pytest.mark.skipif(not GMSSL_AVAILABLE, reason="gmssl dev 依赖缺失")
class TestGmsslInteropCli:
    def _gm_ciphertext(self, mode: int) -> str:
        priv = SM2PrivateKey.from_private_bytes(bytes.fromhex(D_HEX))
        pub_xy = priv.public_key().public_bytes().hex()[2:]  # gmssl 公钥为 x‖y 无前缀
        gm = gmssl_sm2.CryptSM2(private_key=D_HEX, public_key="", mode=mode)
        # 绕开 gmssl __init__ 对 04 开头公钥 lstrip("04") 的误剥离缺陷：构造后直接赋值
        gm.public_key = pub_xy
        return gm.encrypt(b"gmssl cli smoke").hex()

    def test_verify_real_ciphertext_passes(self, capsys):
        assert (
            main(["verify", "--fmt", "C1C2C3", "--privkey", D_HEX, self._gm_ciphertext(0)]) == 0
        )

    def test_verify_real_ciphertext_wrong_order_fails(self, capsys):
        assert (
            main(["verify", "--fmt", "C1C3C2", "--privkey", D_HEX, self._gm_ciphertext(0)]) == 1
        )
