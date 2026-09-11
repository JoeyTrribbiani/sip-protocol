# SIP 加密库（Python 实现）

Agent 间端到端加密通道库：三重 DH 握手 / XChaCha20-Poly1305 / Rekey 前向保密 / 防重放。

完整文档见[仓库根 README](../README.md)与 [docs/architecture.md](../docs/architecture.md)。

## 快速验证

```bash
uv venv --python 3.11 .venv && source .venv/bin/activate
uv pip install -e ".[dev]"
pytest tests/          # 239 passed
```
