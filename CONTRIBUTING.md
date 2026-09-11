# 贡献指南

感谢你考虑为SIP加密库做出贡献！

## 如何贡献

### 报告问题

1. 在 [Issues](https://github.com/JoeyTrribbiani/sip-protocol/issues) 页面搜索现有问题
2. 如果问题不存在，创建新的Issue
3. 提供详细的问题描述、复现步骤和预期结果

### 安全问题

涉及加密实现的安全问题请勿直接开公开 Issue，请在 Issue 中注明"安全问题"并等待维护者私下联系，或直接联系维护者建立私密渠道披露。

### 提交代码

1. Fork 仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 创建 Pull Request

### 代码风格

- Python 代码遵循 [PEP 8](https://www.python.org/dev/peps/pep-0008/) 风格，格式化使用 Black
- Lint 通过 Pylint（10.00/10），类型检查通过 MyPy
- 添加必要的注释和文档（注释中文，标识符英文）

### 测试

- 确保所有测试通过（`cd python && pytest tests/`）
- 添加新功能的测试用例
- 涉及 MCP 四工具的改动必须保持响应结构不变（黄金基线管控）

### 文档

- 更新相关文档
- 添加必要的示例
- 确保文档清晰易懂

## 行为准则

- 尊重他人
- 保持友善和专业
- 接受建设性批评
- 关注对社区最有利的事情

## 联系方式

如有问题，请通过以下方式联系：
- GitHub Issues: https://github.com/JoeyTrribbiani/sip-protocol/issues
