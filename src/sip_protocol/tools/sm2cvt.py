"""SM2 密文互通调试 CLI（GM/T 0003.5 工程互通层，标准协议互通用）。

用法
----
``sip-sm2cvt detect [HEX | --file 路径] [--b64]``
    启发式判别密文线格式（stdout 输出格式标识，含 ASN.1 DER）。

``sip-sm2cvt convert --from FMT --to FMT [HEX | --file 路径] [--b64]
[--out 路径] [--out-b64]``
    五种线格式（四裸格式 + DER）间无损互转（stdout 输出转换后
    hex，``--out-b64`` 时输出 base64）。

``sip-sm2cvt verify --fmt FMT --privkey HEX [HEX | --file 路径] [--b64]``
    用解密方私钥重算 C3（GM/T 0003.4/.5）校验密文完整性，收口
    部分实现 decrypt 不校验 C3 的静默错解。

``sip-sm2cvt decrypt --fmt FMT --privkey HEX [HEX | --file 路径] [--b64]
[--out-b64]``
    GM/T 0003.4/.5 标准 SM2 解密：KDF(x2‖y2)（SM3）还原明文后强制
    复算 C3，认证通过才输出（stdout 单行，缺省 hex，``--out-b64``
    出 base64）——原生解密，不再依赖 gmssl。

亦可以模块方式运行：``python -m sip_protocol.tools.sm2cvt``（子命令同上）。

约定
-----
- 输入优先级：位置参数 → ``--file``（文本文件）→ stdin；密文编码
  缺省 hex（容忍空白字符与 ``0x``/``0X`` 前缀），``--b64`` 切换为
  base64 通道（base64/base64url 自动判别，容忍空白与省略 padding）；
- stdout 恒为机器友好内容（格式标识 / 转换后 hex 或 base64 / 校验
  结论 / 明文 hex 或 base64），提示性说明走 stderr，便于管道脚本消费；
- ``--out-b64`` 输出标准 base64（含 padding，Java/JS 系互通行形态）；
- 退出码：``0`` 成功（verify 通过 / decrypt 解出明文）；``1`` verify
  校验失败 / decrypt C3 复算不一致（错误信息同 verify）；``2`` 输入/
  参数/格式错误（与 argparse 用法错误同码）；
- 本工具属外部系统密文互通范畴，不定义不触碰 SIP-1.0 线协议
  （见 ``crypto/sm2_ciphertext.py`` 模块说明）。
"""

from __future__ import annotations

import argparse
import base64
import sys
from typing import Callable

from ..crypto.sm2 import PRIVATE_KEY_LENGTH, SM2PrivateKey, SM2PublicKey
from ..crypto.sm2_ciphertext import (
    FMT_DER,
    KNOWN_FORMATS,
    Sm2CiphertextFormatError,
    Sm2DecryptError,
    convert,
    decrypt_ciphertext,
    detect_format,
    verify_c3,
)

__all__ = ["main"]


# --- 输入解析 -------------------------------------------------------------


def _read_text(hex_arg: str | None, file_path: str | None) -> str:
    """按 位置参数 → --file → stdin 的优先级读取原始输入文本。"""
    if hex_arg is not None and hex_arg != "-":
        return hex_arg
    if file_path is not None and file_path != "-":
        with open(file_path, encoding="utf-8") as fh:
            return fh.read()
    return sys.stdin.read()


def _decode_b64(text: str) -> bytes:
    """base64/base64url 自动判别解码：容忍空白与省略 padding，严格字母表。"""
    cleaned = "".join(text.split())
    if cleaned[:2].lower() == "0x":
        raise ValueError("--b64 输入不应带 0x 前缀（那是 hex 通道的约定）")
    normalized = cleaned.replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    try:
        return base64.b64decode(normalized, validate=True)
    except ValueError as exc:  # binascii.Error 是 ValueError 子类
        raise ValueError(f"输入不是合法 base64：{exc}") from exc


def _load_ciphertext(hex_arg: str | None, file_path: str | None, b64: bool) -> bytes:
    """读取并解码密文输入：缺省 hex 通道，``b64`` 时走 base64 通道。"""
    text = _read_text(hex_arg, file_path)
    if b64:
        if not "".join(text.split()):
            raise ValueError("输入为空——需要密文 base64（位置参数、--file 或 stdin）")
        return _decode_b64(text)
    cleaned = "".join(text.split())
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    if not cleaned:
        raise ValueError("输入为空——需要密文 hex（位置参数、--file 或 stdin）")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"输入不是合法 hex：{exc}") from exc


def _parse_privkey(privkey_hex: str) -> bytes:
    """解析私钥 hex（容忍 0x 前缀与空白），长度/范围校验交给 SM2 层。"""
    cleaned = "".join(privkey_hex.split())
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    try:
        raw = bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"私钥不是合法 hex：{exc}") from exc
    if len(raw) != PRIVATE_KEY_LENGTH:
        raise ValueError(f"私钥长度非法：{len(raw)} 字节（期望 {PRIVATE_KEY_LENGTH}）")
    return raw


def _make_derive(priv: SM2PrivateKey) -> Callable[[bytes], bytes]:
    """构造 verify_c3 的共享点派生函数：[d]C1 → x2‖y2（含在曲线校验）。"""

    def derive(c1: bytes) -> bytes:
        # C1 为 x‖y 64 字节；SM2PublicKey 解析走 0x04‖x‖y 形态并校验在曲线
        c1_point = SM2PublicKey.from_public_bytes(b"\x04" + c1)
        return priv.exchange_point(c1_point)

    return derive


# --- 子命令 ---------------------------------------------------------------


def _cmd_detect(args: argparse.Namespace) -> int:
    """detect：判别线格式，stdout 输出格式标识。"""
    fmt = detect_format(_load_ciphertext(args.hex, args.file, args.b64))
    print(fmt)
    if fmt == FMT_DER:
        note = "ASN.1 DER 结构完整解析（C1/C3/C2 元素位置由结构自证）"
    elif fmt.endswith("+04"):
        note = "已识别 0x04 前缀（前缀内顺序仍不可判）；C2/C3 顺序无法仅凭字节判别，需私钥复核时用 verify 子命令"
    else:
        note = "未识别到 0x04 前缀（恒按旧序报告）；C2/C3 顺序无法仅凭字节判别，需私钥复核时用 verify 子命令"
    print(f"提示：{note}", file=sys.stderr)
    return 0


def _cmd_convert(args: argparse.Namespace) -> int:
    """convert：五格式无损互转，stdout 输出转换后 hex 或 base64。"""
    out = convert(_load_ciphertext(args.hex, args.file, args.b64), args.from_fmt, args.to_fmt)
    text_out = base64.b64encode(out).decode("ascii") if args.out_b64 else out.hex()
    if args.out is not None:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(text_out + "\n")
        print(f"已写入 {args.out}", file=sys.stderr)
    else:
        print(text_out)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    """verify：重算 C3 校验密文完整性，退出码承载结论（0 通过 / 1 失败）。"""
    priv = SM2PrivateKey.from_private_bytes(_parse_privkey(args.privkey))
    ct = _load_ciphertext(args.hex, args.file, args.b64)
    if verify_c3(ct, args.fmt, _make_derive(priv)):
        print(f"C3 校验通过（格式 {args.fmt}）")
        return 0
    print("C3 校验失败：C3 复算不一致——顺序错配或密文被篡改，可换另一顺序重试")
    return 1


def _cmd_decrypt(args: argparse.Namespace) -> int:
    """decrypt：标准解密并输出明文（hex 或 base64 单行），C3 不一致退出码 1。"""
    privkey_int = int.from_bytes(_parse_privkey(args.privkey), "big")
    ct = _load_ciphertext(args.hex, args.file, args.b64)
    try:
        msg = decrypt_ciphertext(ct, args.fmt, privkey_int)
    except Sm2DecryptError as exc:
        # 文案与 verify 失败路径逐字一致（SIP 错误码前缀不进 CLI 输出）
        print(f"C3 校验失败：{exc.message}")
        return 1
    text_out = base64.b64encode(msg).decode("ascii") if args.out_b64 else msg.hex()
    print(text_out)
    return 0


# --- 入口 -----------------------------------------------------------------


def _add_input_args(parser: argparse.ArgumentParser) -> None:
    """三个子命令共用的密文输入参数。"""
    parser.add_argument("hex", nargs="?", help="密文 hex（缺省读 --file 或 stdin）")
    parser.add_argument("--file", help="从文件读密文文本（hex 或 base64，'-' 亦表示 stdin）")
    parser.add_argument(
        "--b64",
        action="store_true",
        help="输入按 base64 解码（base64/base64url 自动判别，容忍空白与省略 padding）",
    )


def _build_parser() -> argparse.ArgumentParser:
    """构造子命令解析器。"""
    parser = argparse.ArgumentParser(
        prog="sip-sm2cvt",
        description="SM2 加密密文五格式互转与 C3 校验（GM/T 0003.5 工程互通工具）",
        epilog=f"格式标识：{' / '.join(KNOWN_FORMATS)}（裸格式 C1 恒 64 字节 x‖y，C3 恒 32 字节 SM3；DER 为 ASN.1 变长结构）",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_detect = sub.add_parser("detect", help="启发式判别密文线格式")
    _add_input_args(p_detect)
    p_detect.set_defaults(handler=_cmd_detect)

    p_convert = sub.add_parser("convert", help="五种线格式间无损互转")
    p_convert.add_argument(
        "--from", dest="from_fmt", choices=KNOWN_FORMATS, required=True, help="源格式"
    )
    p_convert.add_argument(
        "--to", dest="to_fmt", choices=KNOWN_FORMATS, required=True, help="目标格式"
    )
    _add_input_args(p_convert)
    p_convert.add_argument("--out", help="转换结果写入文件（缺省打印 stdout）")
    p_convert.add_argument(
        "--out-b64",
        action="store_true",
        help="输出按 base64 编码（缺省 hex；Java/JS 系互通行形态）",
    )
    p_convert.set_defaults(handler=_cmd_convert)

    p_verify = sub.add_parser("verify", help="用解密方私钥重算 C3 校验密文完整性")
    p_verify.add_argument("--fmt", choices=KNOWN_FORMATS, required=True, help="声明的线格式")
    p_verify.add_argument(
        "--privkey",
        required=True,
        help=f"解密方私钥 hex（{PRIVATE_KEY_LENGTH} 字节，容忍 0x 前缀）",
    )
    _add_input_args(p_verify)
    p_verify.set_defaults(handler=_cmd_verify)

    p_decrypt = sub.add_parser(
        "decrypt", help="GM/T 0003.5 标准解密（C3 强制校验，输出明文 hex 或 base64）"
    )
    p_decrypt.add_argument("--fmt", choices=KNOWN_FORMATS, required=True, help="声明的线格式")
    p_decrypt.add_argument(
        "--privkey",
        required=True,
        help=f"解密方私钥 hex（{PRIVATE_KEY_LENGTH} 字节，容忍 0x 前缀）",
    )
    _add_input_args(p_decrypt)
    p_decrypt.add_argument(
        "--out-b64",
        action="store_true",
        help="明文按 base64 输出（缺省 hex；stdout 单行）",
    )
    p_decrypt.set_defaults(handler=_cmd_decrypt)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI 入口（console script ``sip-sm2cvt`` 与 ``python -m`` 共用）。"""
    args = _build_parser().parse_args(argv)
    try:
        # set_defaults 注入的 handler 经 Namespace 属性访问为 Any，落定到 int
        exit_code: int = args.handler(args)
        return exit_code
    except (Sm2CiphertextFormatError, ValueError, OSError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
