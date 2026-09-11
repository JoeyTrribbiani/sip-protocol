"""SPEC §14 交叉索引机器校验

docs/SPEC.md 的一致性验证表声称"纸上每条都有测试盯着"——本测试让这句话可执行：
解析交叉索引表中引用的全部测试文件与用例标识符，逐一断言其在 pytest 收集结果中
真实存在。规范引用了不存在的测试（漂移/笔误/删除未同步）即失败。
"""

import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SPEC = REPO / "docs" / "SPEC.md"


def _cross_index_section() -> str:
    text = SPEC.read_text(encoding="utf-8")
    start = text.index("## 14. 一致性验证")
    return text[start:]


def _collected_nodes() -> str:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "tests/"],
        capture_output=True,
        text=True,
        cwd=REPO,
        check=True,
    )
    return result.stdout


def _identifiers(section: str) -> set[str]:
    """Class::test 形式 + 裸 test_* + 裸 Test* 类名（文件名引用先剥离避免词干误匹配）"""
    stripped = re.sub(r"\btest_[a-z0-9_]+\.py\b", "<TESTFILE>", section)
    refs = set()
    refs.update(re.findall(r"\bTest\w+(?:::test_\w+)+\b", stripped))
    refs.update(re.findall(r"\btest_[a-z0-9_]+\b", stripped))
    refs.update(re.findall(r"\bTest\w+\b", stripped))
    return refs


def _test_files(section: str) -> set[str]:
    return set(re.findall(r"\btest_[a-z0-9_]+\.py\b", section))


def test_spec_references_only_existing_test_files():
    for name in _test_files(_cross_index_section()):
        assert (REPO / "tests" / name).is_file(), f"SPEC §14 引用的测试文件不存在: {name}"


def test_spec_references_only_existing_test_ids():
    section = _cross_index_section()
    nodes = _collected_nodes()
    missing = []
    for ident in sorted(_identifiers(section)):
        if "::" in ident:
            ok = ident in nodes
        elif ident.startswith("test_"):
            ok = f"::{ident}" in nodes
        else:  # 类名
            ok = f"::{ident}::" in nodes
        if not ok:
            missing.append(ident)
    assert not missing, f"SPEC §14 引用了 pytest 收集结果中不存在的用例: {missing}"


def test_spec_index_covers_all_protocol_sections():
    """交叉索引表必须覆盖 §4-§9 与 §11（协议 wire 语义章节不可缺行）"""
    section = _cross_index_section()
    for required in ("§4 握手", "§5", "§6", "§7 Rekey", "§8", "§9 SIPFT", "§11"):
        assert required in section, f"交叉索引缺 {required} 章节"
