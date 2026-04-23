# HTTP 传输层适配器设计文档

> 版本: v1.0
> 日期: 2026-04-22
> 状态: 已批准
> 关联: S3 (sip-protocol-report.md Section 8.5.1 S3)

## 1. 问题陈述

当前SIP的传输层只有WebSocket（已实现）和OpenClaw适配器（stdio）。缺少标准HTTP/REST传输，无法与企业系统集成、无法通过NAT、无法利用现有HTTP基础设施。

## 2. 设计原则

1. **Client/Server分离** — 明确HTTP模式需要Message Broker中间层
2. **长轮询接收** — 不用短轮询，使用timeout=30s的长轮询
3. **REST端点完整** — 覆盖所有SIP操作
4. **继承TransportBase** — 与现有WebSocket适配器一致

## 3. 架构：需要Message Broker中间层

HTTP模式下，Agent是Client，中间有一个Message Broker作为Server：

```
┌──────────────┐    HTTP/REST    ┌──────────────────┐    HTTP/REST    ┌──────────────┐
│  Agent A     │ ←──────────────→ │  Message Broker  │ ←──────────────→ │  Agent B     │
│  (Client)    │                 │  (Server)        │                 │  (Client)    │
└──────────────┘                 └──────────────────┘                 └──────────────┘
                                         │
                                  ┌──────────┼──────────┐
                                  │ 消息路由    │ 心跳检查  │
                                  │ Agent注册  │ 持久化   │
                                  └─────────────────────┘
```

**为什么不直接P2P HTTP？**
- Agent跑在localhost，没有固定端口，无法直接被HTTP Client访问
- Agent可能在不同机器、NAT后面
- Message Broker提供消息缓冲、路由、持久化

**Message Broker实现**：
- 轻量级：基于Python标准库`http.server`或FastAPI
- 可选部署：单机（开发）/ Docker（生产）/ 云服务（托管）
- 最简方案：复用现有的Agent Registry作为Broker

## 4. REST API 端点

```
消息操作:
POST /sip/send              发送加密消息
GET  /sip/receive            接收消息（长轮询，timeout=30s）
POST /sip/handshake          发起/完成握手
POST /sip/rekey              密钥轮换

连接管理:
GET  /sip/status             连接状态查询
POST /sip/connect            注册连接
POST /sip/disconnect         断开连接

Agent查询:
GET  /sip/agents             查询在线Agent（配合S4 Registry）
GET  /sip/agents/{name}      查询指定AgentCard

健康检查:
GET  /sip/health             Broker健康状态
```

## 5. HTTPTransportAdapter

```python
class HTTPTransportAdapter(TransportBase):
    """HTTP/REST传输适配器（Client端）"""

    def __init__(
        self,
        broker_url: str,
        agent_id: str,
        auth_manager: AuthManager | None = None,
    ):
        self._broker_url = broker_url.rstrip("/")
        self._agent_id = agent_id
        self._auth_manager = auth_manager
        self._session: requests.Session | None = None

    def connect(self) -> None:
        """注册到Broker"""
        self._session = requests.Session()
        resp = self._post("/sip/connect", {
            "agent_id": self._agent_id,
        })
        if resp.status_code != 200:
            raise SIPConnectionError(f"Failed to connect: {resp.text}")

    def send(self, message: bytes) -> dict:
        """发送加密消息到Broker"""
        resp = self._post("/sip/send", {
            "sender_id": self._agent_id,
            "payload": base64.b64encode(message).decode(),
            "timestamp": time.time(),
        })
        return resp.json()

    def receive(self, timeout: float = 30.0) -> dict | None:
        """长轮询接收消息（timeout默认30秒）"""
        resp = self._session.get(
            f"{self._broker_url}/sip/receive",
            params={"agent_id": self._agent_id, "timeout": timeout},
            timeout=timeout + 5,  # 额外5秒网络延迟
        )
        if resp.status_code == 204:  # No Content
            return None
        return resp.json()

    def handshake(self, message: dict) -> dict:
        """发送握手消息"""
        resp = self._post("/sip/handshake", message)
        return resp.json()

    def rekey(self, message: dict) -> dict:
        """发送Rekey消息"""
        resp = self._post("/sip/rekey", message)
        return resp.json()

    def close(self) -> None:
        """断开连接"""
        if self._session:
            try:
                self._post("/sip/disconnect", {"agent_id": self._agent_id})
            except Exception:
                pass
            self._session.close()
            self._session = None

    def _post(self, path: str, data: dict) -> "requests.Response":
        """辅助方法：发送POST请求"""
        headers = {"Content-Type": "application/json"}
        if self._auth_manager:
            # 添加认证头
            token = self._auth_manager.get_current_token()
            if token:
                headers["Authorization"] = f"Bearer {token}"
        return self._session.post(  # type: ignore
            f"{self._broker_url}{path}",
            json=data,
            headers=headers,
            timeout=10,
        )
```

## 6. 消息路由

Message Broker根据SIP Message Schema中的`recipient_type`路由：

```python
class MessageRouter:
    """消息路由器（Broker端）"""

    def route(self, message: dict) -> list[str]:
        """根据消息确定目标Agent列表"""
        recipient_type = message.get("recipient_type", "direct")

        if recipient_type == "direct":
            return [message["recipient_id"]]
        elif recipient_type == "group":
            # 查询群组成员列表
            group_id = message["recipient_group"]
            return self._registry.get_group_members(group_id)
        elif recipient_type == "broadcast":
            return [a.name for a in self._registry.list_online()]
        return []
```

## 7. TLS配置

```python
TLS_CONFIG = {
    "min_version": "TLS 1.2",
    "cipher_suites": [
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
    ],
    "cert_verification": True,        # 生产环境必须验证证书
    "ca_file": None,                   # 自定义CA证书
}
```

## 8. 模块位置

```
python/src/sip_protocol/
├── transport/
│   ├── http_adapter.py       # HTTPTransportAdapter (Client)
│   ├── http_broker.py        # MessageBroker (Server)
│   └── router.py            # MessageRouter
```

## 9. 实现依赖

- `requests` — HTTP客户端（或使用标准库`urllib`）
- Message Broker Server — FastAPI或标准库http.server
- TLS — Python标准库`ssl`
