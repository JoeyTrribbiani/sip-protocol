# 贡献指南

感谢你对SIP协议项目的关注和贡献！

## 开发流程

### 1. Fork项目
1. 访问 https://github.com/JoeyTrribbiani/sip-protocol
2. 点击"Fork"按钮

### 2. 克隆仓库
```bash
git clone https://github.com/YOUR_USERNAME/sip-protocol.git
cd sip-protocol/javascript
```

### 3. 创建功能分支
```bash
git checkout -b feature/your-feature-name
```

### 4. 安装依赖
```bash
npm install
```

### 5. 运行测试
```bash
npm test
```

### 6. 代码格式化
```bash
npm run format
```

### 7. 代码检查
```bash
npm run lint
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

### JavaScript
- 使用ES6+语法
- 使用async/await处理异步操作
- 遵循[ESLint](https://eslint.org/)规则
- 使用[Prettier](https://prettier.io/)格式化

### 注释规范
- 所有公开函数必须有JSDoc注释
- 复杂逻辑必须有行内注释
- 使用中文注释（项目定位为中文社区）

```javascript
/**
 * 派生消息密钥
 * @param {Buffer} chainKey - 链密钥
 * @param {Buffer} salt - 盐
 * @param {Buffer} info - 上下文信息
 * @returns {Buffer} 消息密钥
 */
function deriveMessageKey(chainKey, salt, info) {
  // 实现细节
}
```

## 测试规范

### 单元测试
- 测试文件命名：`test_*.js`（单元测试）、`integration_*.js`（集成测试）、`e2e_*.js`（端到端测试）
- 每个函数至少有一个测试用例
- 测试覆盖率 > 80%

```javascript
test('应该正确派生消息密钥', () => {
  const chainKey = Buffer.from('...');
  const salt = Buffer.alloc(0);
  const info = Buffer.from('message-key');

  const messageKey = deriveMessageKey(chainKey, salt, info);

  expect(messageKey).toBeDefined();
  expect(messageKey.length).toBe(32);
});
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

- 使用加密安全的随机数生成器
- 使用常数时间比较（`crypto.timingSafeEqual`）
- 验证所有输入参数
- 避免侧信道攻击
- 定期更新依赖

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

4. 发布到npm（如果需要）
```bash
npm publish
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
