# 标准认证集成设计文档

> 版本: v1.0
> 日期: 2026-04-22
> 状态: 已批准
> 关联: M4 (sip-protocol-report.md Section 8.5.2 M4)

## 1. 问题陈述

当前SIP只有PSK预共享密钥认证，无法支持动态Agent网络的信任建立。
需要支持多种认证方案（PSK/Bearer/API Key/OAuth2/mTLS），同时保持与现有PSK流程兼容。

## 2. 设计原则

1. **PSK特殊处理** — PSK是现有流程，不走Bearer/Token路径，直接进Triple DH握手
2. **明文交换** — AgentCard交换在加密通道建立前完成（AgentCard是公开信息），认证后通信加密
3. **协商优先** — 双方先交换支持的认证方案，再选择共同支持的最佳方案
4. **同步API** — 与现有SIP项目一致

## 3. 认证类型

```python
class AuthType(str, Enum):
    PSK = "psk"           # 预共享密钥（已有，特殊路径）
    BEARER = "bearer"     # JWT Bearer Token
    API_KEY = "api_key"   # API Key（静态）
    OAUTH2 = "oauth2"     # OAuth 2.0 / OIDC
    MTLS = "mtls"         # 双向TLS


# 方案优先级（从高到低）
AUTH_PRIORITY = [
    AuthType.MTLS,       # 最安全
    AuthType.OAUTH2,     # 标准化
    AuthType.BEARER,     # 通用
    AuthType.API_KEY,    # 简单
    AuthType.PSK,        # 最基础（兼容现有）
]
```

## 4. 认证结果

```python
@dataclass
class AuthResult:
    """认证结果"""
    success: bool
    agent_id: str | None = None
    auth_type: AuthType | None = None
    error: str | None = None
    token: str | None = None             # Bearer token（Bearer/OAuth2场景）
    expires_at: float | None = None      # token过期时间戳
```

## 5. AuthHandler 接口

每种认证方案实现一个Handler：

```python
from abc import ABC, abstractmethod


class AuthHandler(ABC):
    """认证方案处理器抽象接口"""

    @property
    @abstractmethod
    def auth_type(self) -> AuthType:
        """此处理器处理的认证类型"""

    @abstractmethod
    def authenticate(self, credentials: dict[str, Any]) -> AuthResult:
        """验证凭证"""

    @abstractmethod
    def can_handle(self, auth_type: AuthType) -> bool:
        """是否支持指定认证类型"""


class PSKHandler(AuthHandler):
    """PSK认证处理器 — 特殊路径，直接用已有的Argon2id PSK验证"""

    @property
    def auth_type(self) -> AuthType:
        return AuthType.PSK

    def authenticate(self, credentials: dict[str, Any]) -> AuthResult:
        psk = credentials.get("psk")
        if not psk:
            return AuthResult(success=False, error="缺少PSK")
        # PSK验证在handshake.py的hash_psk()中完成
        # 这里只做格式检查
        return AuthResult(success=True, auth_type=AuthType.PSK)

    def can_handle(self, auth_type: AuthType) -> bool:
        return auth_type == AuthType.PSK


class BearerHandler(AuthHandler):
    """Bearer Token认证处理器"""

    def __init__(self, public_keys: dict[str, str] | None = None):
        self._public_keys = public_keys or {}

    @property
    def auth_type(self) -> AuthType:
        return AuthType.BEARER

    def authenticate(self, credentials: dict[str, Any]) -> AuthResult:
        token = credentials.get("token")
        if not token:
            return AuthResult(success=False, error="缺少Bearer Token")
        # 验证JWT签名、过期时间等
        try:
            payload = self._verify_jwt(token)
            return AuthResult(
                success=True,
                agent_id=payload.get("sub"),
                auth_type=AuthType.BEARER,
                token=token,
                expires_at=payload.get("exp"),
            )
        except Exception as e:
            return AuthResult(success=False, error=str(e))

    def can_handle(self, auth_type: AuthType) -> bool:
        return auth_type == AuthType.BEARER


class ApiKeyHandler(AuthHandler):
    """API Key认证处理器"""

    def __init__(self, valid_keys: dict[str, str] | None = None):
        # key_id → agent_id 的映射
        self._valid_keys = valid_keys or {}

    @property
    def auth_type(self) -> AuthType:
        return AuthType.API_KEY

    def authenticate(self, credentials: dict[str, Any]) -> AuthResult:
        api_key = credentials.get("api_key")
        if not api_key:
            return AuthResult(success=False, error="缺少API Key")
        agent_id = self._valid_keys.get(api_key)
        if agent_id is None:
            return AuthResult(success=False, error="无效的API Key")
        return AuthResult(success=True, agent_id=agent_id, auth_type=AuthType.API_KEY)

    def can_handle(self, auth_type: AuthType) -> bool:
        return auth_type == AuthType.API_KEY
```

## 6. AuthManager

```python
class AuthManager:
    """认证管理器 — 协调多种认证方案"""

    def __init__(self):
        self._handlers: dict[AuthType, AuthHandler] = {}
        # 默认注册PSK处理器（向后兼容）
        self.register_handler(PSKHandler())

    def register_handler(self, handler: AuthHandler) -> None:
        """注册认证方案处理器"""
        self._handlers[handler.auth_type] = handler

    def authenticate(self, auth_type: AuthType, credentials: dict[str, Any]) -> AuthResult:
        """执行认证"""
        handler = self._handlers.get(auth_type)
        if handler is None:
            return AuthResult(success=False, error=f"不支持的认证方案: {auth_type}")
        return handler.authenticate(credentials)

    def negotiate(self, local: list[AuthType], remote: list[AuthType]) -> AuthType | None:
        """协商双方共同支持的认证方案

        按AUTH_PRIORITY优先级选择第一个共同支持的方案。
        PSK作为兜底方案总是可选的。
        """
        common = set(local) & set(remote)
        if not common:
            return None
        for auth_type in AUTH_PRIORITY:
            if auth_type in common:
                return auth_type
        return None

    def supported_types(self) -> list[AuthType]:
        """返回已注册的所有认证方案"""
        return list(self._handlers.keys())
```

## 7. 认证流程

### 7.1 PSK路径（现有流程，不变）

```
Agent A ←→ Agent B
  │
  ├── PSK已在双方配置（环境变量/配置文件）
  ├── 直接进入SIP Triple DH握手
  ├── handshake.py 内部调用 hash_psk(psk) 验证
  └── 认证+握手一步完成
```

### 7.2 新认证方案路径

```
Agent A ←→ Agent B
  │
  ├── 1. 交换AgentCard（明文，包含各自支持的认证方案列表）
  ├── 2. negotiate() 选择共同支持的认证方案（如 Bearer）
  ├── 3. 交换凭证（通过AgentCard中声明的端点）
  │     Agent B: authenticate(bearer, {token: "jwt..."})
  ├── 4. 认证成功
  ├── 5. 进入SIP Triple DH握手（用认证后的身份建立加密通道）
  └── 6. 加密通道建立后所有通信加密
```

### 7.3 安全边界说明

| 阶段 | 是否加密 | 说明 |
|------|---------|------|
| AgentCard交换 | 否（明文） | AgentCard是公开信息，不含敏感数据 |
| 凭证交换 | 是（TLS） | 通过HTTPS端点传输凭证 |
| SIP握手 | 是（E2EE） | Triple DH + XChaCha20-Poly1305 |
| 业务消息 | 是（E2EE） | SIP加密通道 |

## 8. 模块位置

```
python/src/sip_protocol/
├── auth/
│   ├── __init__.py
│   ├── types.py          # AuthType, AuthResult, AuthConfig
│   ├── manager.py        # AuthManager
│   ├── base.py           # AuthHandler 抽象接口
│   ├── psk_handler.py    # PSKHandler
│   ├── bearer_handler.py # BearerHandler
│   └── apikey_handler.py # ApiKeyHandler
```
