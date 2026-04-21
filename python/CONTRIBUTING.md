# Python贡献指南

感谢你对SIP协议项目的关注和贡献！

## 开发流程

### 1. Fork项目
1. 访问 https://github.com/JoeyTrribbiani/sip-protocol
2. 点击"Fork"按钮

### 2. 克隆仓库
```bash
git clone https://github.com/YOUR_USERNAME/sip-protocol.git
cd sip-protocol/python
```

### 3. 创建虚拟环境
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate  # Windows
```

### 4. 安装依赖
```bash
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### 5. 运行测试
```bash
pytest tests/
pytest tests/unit/
pytest tests/integration/
pytest tests/e2e/
```

### 6. 代码检查
```bash
pylint src/
black src/ --check
mypy src/
```

## 提交规范

使用 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

- `feat:` 新功能
- `fix:` 修复bug
- `docs:` 文档更新
- `style:` 代码格式（不影响功能）
- `refactor:` 重构
- `perf:` 性能优化
- `test:` 测试相关
- `chore:` 构建/工具相关

示例：
```bash
git commit -m "feat: 添加群组加密支持"
git commit -m "fix: 修复HKDF密钥派生的bug"
```

## 代码规范

### Python
- 遵循PEP 8风格指南
- 使用Black格式化
- 使用类型注解（Type Hints）
- 使用pylint检查代码质量
- 使用mypy进行类型检查

### 命名规范
- 类名：PascalCase（如 `GroupManager`）
- 函数名：snake_case（如 `generate_keypair`）
- 常量：UPPER_SNAKE_CASE（如 `AES_GCM_NONCE_LENGTH`）
- 私有方法：前缀单下划线（如 `_internal_method`）

### 注释规范
- 所有公开函数必须有docstring
- 使用Google风格docstring
- 复杂逻辑必须有行内注释
- 使用中文注释（项目定位为中文社区）

```python
def derive_message_key(chain_key: bytes, salt: bytes, info: bytes) -> bytes:
    """派生消息密钥

    Args:
        chain_key: 链密钥
        salt: 盐
        info: 上下文信息

    Returns:
        消息密钥
    """
    # 实现细节
    pass
```

## 测试规范

### 单元测试
- 测试文件命名：`test_*.py`
- 使用pytest框架
- 每个函数至少有一个测试用例
- 测试覆盖率 > 80%

```python
def test_derive_message_key():
    """应该正确派生消息密钥"""
    chain_key = b"..."
    salt = b""
    info = b"message-key"

    message_key = derive_message_key(chain_key, salt, info)

    assert message_key is not None
    assert len(message_key) == 32
```

### 集成测试
- 测试模块间的交互
- 使用真实的加密操作
- 验证端到端流程

### 端到端测试
- 测试完整的用户场景
- 模拟真实的使用环境
- 验证性能指标

## Pull Request流程

1. 提交PR到`main`分支
2. PR标题遵循Conventional Commits规范
3. PR描述必须包含：
   - 改动说明
   - 相关Issue编号
   - 测试结果
   - 截图（如果涉及UI）
4. 等待代码审查
5. 根据反馈修改代码
6. 合并到main分支

## 性能要求

- DH密钥交换 < 10ms
- HKDF密钥派生 < 5ms
- AES-GCM加密（1KB） < 1ms
- 群组消息加密（顺序） < 0.5ms
- 群组消息加密（乱序） < 2ms

## 安全要求

- 使用加密安全的随机数生成器（`secrets`或`os.urandom`）
- 使用恒定时间比较（`hmac.compare_digest`）
- 验证所有输入参数
- 避免侧信道攻击
- 定期更新依赖（`pip-audit`）

## 文档要求

- 所有公开API必须有文档
- 更新README.md（如果有新功能）
- 更新CHANGELOG.md
- 提供使用示例

## 发布流程

1. 更新版本号（遵循[Semantic Versioning](https://semver.org/)）
   - MAJOR: 不兼容的API更改
   - MINOR: 向后兼容的新功能
   - PATCH: 向后兼容的bug修复

2. 更新CHANGELOG.md

3. 创建Git标签
```bash
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0
```

4. 发布到PyPI（如果需要）
```bash
python setup.py sdist bdist_wheel
twine upload dist/*
```

## 社区准则

- 尊重所有贡献者
- 建设性反馈
- 乐于助人
- 持续学习

## 联系方式

- GitHub Issues: https://github.com/JoeyTrribbiani/sip-protocol/issues
- Email: [your-email@example.com]

---

感谢你的贡献！🎉
