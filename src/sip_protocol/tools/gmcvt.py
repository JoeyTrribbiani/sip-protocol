"""SM3 杂凑 / HMAC-SM3 / HKDF-SM3 国密互通计算 CLI（GM/T 0004 + RFC 5869）。

用法
----
``sip-gmcvt sm3 [文本 | --file 路径] [--hex | --b64]``
    SM3 杂凑（GM/T 0004 / GB/T 32905），stdout 输出 32 字节 digest hex。

``sip-gmcvt hmac-sm3 --key HEX [文本 | --file 路径] [--hex | --b64]``
    HMAC-SM3（RFC 2104 构造），stdout 输出 32 字节 MAC hex。

``sip-gmcvt hkdf-sm3 [--salt HEX] [--info HEX] [--len N] [文本 | --file 路径]
[--hex | --b64]``
    HKDF-SM3 密钥派生（RFC 5869 构造、SM3 作 PRF），输入 IKM，stdout
    输出 OKM hex。

亦可以模块方式运行：``python -m sip_protocol.tools.gmcvt``（子命令同上）。

约定
-----
- 输入优先级：位置参数 → ``--file``（UTF-8 文本文件）→ stdin；
- 消息编码缺省文本（按 UTF-8 字节），``--hex``/``--b64``（互斥）切换
  编码通道——与 ``sip-sm2cvt`` 缺省 hex 通道相反：杂凑/派生的日常输入
  是文本，密文工具的输入才是 hex。hex 容忍空白与 ``0x`` 前缀；
  base64/base64url 自动判别、容忍换行与省略 padding；
- 文本通道剥单个尾随换行（``\n`` 或 ``\r\n``，echo/编辑器尾换行友好），
  其余字节原样参与计算；需精确字节控制时用 ``--hex``/``--b64`` 通道；
- 空输入视为空消息（杂凑/派生上合法且有标准摘要），与密文工具的
  拒收语义不同；
- ``--salt``/``--info`` 缺省空字节串——RFC 5869 未提供盐即 HashLen 全零
  盐，空盐经 HMAC 零填充语义与全零盐逐字节等价；``--len`` 缺省 32，
  上界 255×32=8160（RFC 5869 N 上限）；
- stdout 恒为机器友好内容（digest/MAC/OKM hex），提示性说明走 stderr；
- 退出码：``0`` 成功；``2`` 输入/参数/格式错误（与 argparse 用法错误
  同码）；
- 本工具属外部系统互通调试范畴，不定义不触碰 SIP-1.0 线协议。
"""

from __future__ import annotations

import argparse
import base64
import sys

from ..crypto.hkdf import hkdf
from ..crypto.sm3 import SM3_DIGEST_SIZE, hmac_sm3, sm3_hash
from ..crypto.suite import SUITE_ZH

__all__ = ["main"]

# RFC 5869 输出上界：N ≤ 255 × HashLen（SM3 为 32 字节）
HKDF_SM3_MAX_LENGTH = 255 * SM3_DIGEST_SIZE


# --- 输入解析 -------------------------------------------------------------


def _read_text(text_arg: str | None, file_path: str | None) -> str:
    """按 位置参数 → --file → stdin 的优先级读取原始输入文本。"""
    if text_arg is not None and text_arg != "-":
        return text_arg
    if file_path is not None and file_path != "-":
        with open(file_path, encoding="utf-8") as fh:
            return fh.read()
    return sys.stdin.read()


def _strip_trailing_newline(text: str) -> str:
    """剥单个尾随换行（``\\n`` 或 ``\\r\\n``）——echo/编辑器尾换行友好。"""
    if text.endswith("\r\n"):
        return text[:-2]
    if text.endswith("\n"):
        return text[:-1]
    return text


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


def _decode_hex(text: str) -> bytes:
    """hex 解码：容忍空白字符与 ``0x``/``0X`` 前缀，空输入解码为空消息。"""
    cleaned = "".join(text.split())
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"输入不是合法 hex：{exc}") from exc


def _load_message(
    text_arg: str | None, file_path: str | None, hex_channel: bool, b64_channel: bool
) -> bytes:
    """读取消息并按通道解码：缺省文本（UTF-8 字节），``--hex``/``--b64`` 切编码通道。

    任意通道的空输入均视为空消息（杂凑/派生上合法）。
    """
    text = _read_text(text_arg, file_path)
    if b64_channel:
        return _decode_b64(text)
    if hex_channel:
        return _decode_hex(text)
    return _strip_trailing_newline(text).encode("utf-8")


def _parse_hex_param(label: str, value: str) -> bytes:
    """解析 --key/--salt/--info 类 hex 参数（容忍 0x 前缀与空白）。"""
    cleaned = "".join(value.split())
    if cleaned[:2].lower() == "0x":
        cleaned = cleaned[2:]
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"{label} 不是合法 hex：{exc}") from exc


# --- 子命令 ---------------------------------------------------------------


def _cmd_sm3(args: argparse.Namespace) -> int:
    """sm3：GM/T 0004 杂凑，stdout 输出 digest hex。"""
    print(sm3_hash(_load_message(args.text, args.file, args.hex_channel, args.b64_channel)).hex())
    return 0


def _cmd_hmac_sm3(args: argparse.Namespace) -> int:
    """hmac-sm3：RFC 2104 构造，stdout 输出 MAC hex。"""
    key = _parse_hex_param("--key", args.key)
    message = _load_message(args.text, args.file, args.hex_channel, args.b64_channel)
    print(hmac_sm3(key, message).hex())
    return 0


def _cmd_hkdf_sm3(args: argparse.Namespace) -> int:
    """hkdf-sm3：RFC 5869 构造（SM3 作 PRF），stdout 输出 OKM hex。"""
    if not 1 <= args.length <= HKDF_SM3_MAX_LENGTH:
        raise ValueError(
            f"--len 越界：{args.length}（合法 1..{HKDF_SM3_MAX_LENGTH}，RFC 5869 上限 255×32）"
        )
    ikm = _load_message(args.text, args.file, args.hex_channel, args.b64_channel)
    salt = _parse_hex_param("--salt", args.salt)
    info = _parse_hex_param("--info", args.info)
    # 复用 crypto/hkdf.py 的 ZH 路径——与线协议密钥调度同一实现（SPEC §5）
    print(hkdf(ikm, salt, info, args.length, SUITE_ZH).hex())
    return 0


# --- 入口 -----------------------------------------------------------------


def _add_input_args(parser: argparse.ArgumentParser) -> None:
    """三个子命令共用的消息输入参数。"""
    parser.add_argument(
        "text",
        nargs="?",
        help="消息文本（缺省按 UTF-8 字节；--hex/--b64 时为编码文本；空输入视为空消息）",
    )
    parser.add_argument("--file", help="从文件读消息文本（'-' 亦表示 stdin）")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--hex",
        dest="hex_channel",
        action="store_true",
        help="输入按 hex 解码（容忍空白与 0x 前缀）",
    )
    group.add_argument(
        "--b64",
        dest="b64_channel",
        action="store_true",
        help="输入按 base64 解码（base64/base64url 自动判别，容忍空白与省略 padding）",
    )


def _build_parser() -> argparse.ArgumentParser:
    """构造子命令解析器。"""
    parser = argparse.ArgumentParser(
        prog="sip-gmcvt",
        description="SM3 / HMAC-SM3 / HKDF-SM3 国密互通计算（GM/T 0004 + RFC 5869 工具）",
        epilog=(
            "消息编码缺省文本（UTF-8 字节），--hex/--b64 互斥切换编码通道；"
            "hkdf-sm3 的 --salt/--info 缺省空（RFC 5869 全零盐等价），--len 缺省 32、"
            f"上界 {HKDF_SM3_MAX_LENGTH}"
        ),
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_sm3 = sub.add_parser("sm3", help="SM3 杂凑（GM/T 0004，digest hex 输出）")
    _add_input_args(p_sm3)
    p_sm3.set_defaults(handler=_cmd_sm3)

    p_hmac = sub.add_parser("hmac-sm3", help="HMAC-SM3（RFC 2104 构造，MAC hex 输出）")
    p_hmac.add_argument(
        "--key",
        required=True,
        help="密钥 hex（任意长度，容忍 0x 前缀；空 hex 即空密钥，RFC 2104 合法）",
    )
    _add_input_args(p_hmac)
    p_hmac.set_defaults(handler=_cmd_hmac_sm3)

    p_hkdf = sub.add_parser("hkdf-sm3", help="HKDF-SM3 密钥派生（RFC 5869，OKM hex 输出）")
    p_hkdf.add_argument(
        "--salt",
        default="",
        help="盐 hex（缺省空 = RFC 5869 未提供盐，全零盐等价）",
    )
    p_hkdf.add_argument("--info", default="", help="上下文信息 hex（缺省空）")
    p_hkdf.add_argument(
        "--len",
        dest="length",
        type=int,
        default=SM3_DIGEST_SIZE,
        help=f"输出 OKM 字节数（缺省 {SM3_DIGEST_SIZE}，上界 {HKDF_SM3_MAX_LENGTH}）",
    )
    _add_input_args(p_hkdf)
    p_hkdf.set_defaults(handler=_cmd_hkdf_sm3)

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI 入口（console script ``sip-gmcvt`` 与 ``python -m`` 共用）。"""
    args = _build_parser().parse_args(argv)
    try:
        # set_defaults 注入的 handler 经 Namespace 属性访问为 Any，落定到 int
        exit_code: int = args.handler(args)
        return exit_code
    except (ValueError, OSError) as exc:
        print(f"错误: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
