"""SM2 密文互通调试 CLI（GM/T 0003.5 工程互通层，标准协议互通用）。

用法
----
``sip-sm2cvt detect [HEX | --file 路径]``
    启发式判别密文线格式（stdout 输出格式标识）。

``sip-sm2cvt convert --from FMT --to FMT [HEX | --file 路径] [--out 路径]``
    四种线格式间无损互转（stdout 输出转换后 hex）。

``sip-sm2cvt verify --fmt FMT --privkey HEX [HEX | --file 路径]``
    用解密方私钥重算 C3（GM/T 0003.4/.5）校验密文完整性，收口
    部分实现 decrypt 不校验 C3 的静默错解。

亦可以模块方式运行：``python -m sip_protocol.tools.sm2cvt``（子命令同上）。

约定
-----
- 输入优先级：位置参数 hex → ``--file``（hex 文本文件）→ stdin；
  hex 容忍空白字符（换行/空格统一剥离）与 ``0x``/``0X`` 前缀；
- stdout 恒为机器友好内容（格式标识 / 转换后 hex / 校验结论），
  提示性说明走 stderr，便于管道脚本消费；
- 退出码：``0`` 成功（verify 通过）；``1`` verify 校验失败；
  ``2`` 输入/参数/格式错误（与 argparse 用法错误同码）；
- 本工具属外部系统密文互通范畴，不定义不触碰 SIP-1.0 线协议
  （见 ``crypto/sm2_ciphertext.py`` 模块说明）。
"""

from __future__ import annotations

import argparse
import sys
from typing import Callable

from ..crypto.sm2 import PRIVATE_KEY_LENGTH, SM2PrivateKey, SM2PublicKey
from ..crypto.sm2_ciphertext import (
    KNOWN_FORMATS,
    Sm2CiphertextFormatError,
    convert,
    detect_format,
    verify_c3,
)

__all__ = ["main"]


# --- 输入解析 -------------------------------------------------------------


def _load_hex(hex_arg: str | None, file_path: str | None) -> bytes:
    """按 位置参数 → --file → stdin 的优先级读取并解析密文 hex。"""
    if hex_arg is not None and hex_arg != "-":
        text = hex_arg
    elif file_path is not None and file_path != "-":
        with open(file_path, encoding="utf-8") as fh:
            text = fh.read()
    else:
        text = sys.stdin.read()
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
    fmt = detect_format(_load_hex(args.hex, args.file))
    print(fmt)
    prefix_note = (
        "已识别 0x04 前缀（前缀内顺序仍不可判）"
        if fmt.endswith("+04")
        else "未识别到 0x04 前缀（恒按旧序报告）"
    )
    print(
        f"提示：{prefix_note}；C2/C3 顺序无法仅凭字节判别，" "需私钥复核时用 verify 子命令",
        file=sys.stderr,
    )
    return 0


def _cmd_convert(args: argparse.Namespace) -> int:
    """convert：四格式无损互转，stdout 输出转换后 hex。"""
    out = convert(_load_hex(args.hex, args.file), args.from_fmt, args.to_fmt)
    hex_out = out.hex()
    if args.out is not None:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(hex_out + "\n")
        print(f"已写入 {args.out}", file=sys.stderr)
    else:
        print(hex_out)
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    """verify：重算 C3 校验密文完整性，退出码承载结论（0 通过 / 1 失败）。"""
    priv = SM2PrivateKey.from_private_bytes(_parse_privkey(args.privkey))
    if verify_c3(_load_hex(args.hex, args.file), args.fmt, _make_derive(priv)):
        print(f"C3 校验通过（格式 {args.fmt}）")
        return 0
    print("C3 校验失败：C3 复算不一致——顺序错配或密文被篡改，可换另一顺序重试")
    return 1


# --- 入口 -----------------------------------------------------------------


def _add_input_args(parser: argparse.ArgumentParser) -> None:
    """三个子命令共用的密文输入参数。"""
    parser.add_argument("hex", nargs="?", help="密文 hex（缺省读 --file 或 stdin）")
    parser.add_argument("--file", help="从文件读密文 hex 文本（'-' 亦表示 stdin）")


def _build_parser() -> argparse.ArgumentParser:
    """构造子命令解析器。"""
    parser = argparse.ArgumentParser(
        prog="sip-sm2cvt",
        description="SM2 加密密文四格式互转与 C3 校验（GM/T 0003.5 工程互通工具）",
        epilog=f"格式标识：{' / '.join(KNOWN_FORMATS)}（C1 恒 64 字节 x‖y，C3 恒 32 字节 SM3）",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_detect = sub.add_parser("detect", help="启发式判别密文线格式")
    _add_input_args(p_detect)
    p_detect.set_defaults(handler=_cmd_detect)

    p_convert = sub.add_parser("convert", help="四种线格式间无损互转")
    p_convert.add_argument(
        "--from", dest="from_fmt", choices=KNOWN_FORMATS, required=True, help="源格式"
    )
    p_convert.add_argument(
        "--to", dest="to_fmt", choices=KNOWN_FORMATS, required=True, help="目标格式"
    )
    _add_input_args(p_convert)
    p_convert.add_argument("--out", help="转换结果 hex 写入文件（缺省打印 stdout）")
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
