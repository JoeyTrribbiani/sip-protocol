# QUIC + WebRTC 传输层设计文档

> 版本: v1.0
> 日期: 2026-04-22
> 状态: 概念设计（暂不实现）
> 关联: L2 (agent-chat-architecture.md Phase 3)

## 1. 问题陈述

当前SIP传输层基于TCP（WebSocket/HTTP），在弱网环境、NAT穿透、高延迟场景下表现受限。

## 2. 为什么现在不做

### QUIC的Python生态问题
- `aioquic`是主要选择，但维护活跃度低
- 与Python 3.14兼容性存疑
- 引入asyncio依赖与现有同步代码冲突

### WebRTC在Agent场景的ROI不足
- WebRTC核心优势是NAT穿透+实时媒体
- Agent通信主要是文本/结构化数据
- 复杂度高（ICE/STUN/TURN/SDP协商）

### 当前优先级不够
- HTTP+WebSocket（已有）足够覆盖局域网和基础互联网场景
- 有明确的高延迟/NAT穿透需求时再做

## 3. 概念设计（供未来参考）

### 3.1 传输层选择矩阵

| 场景 | 推荐传输 | 理由 |
|------|---------|------|
| 局域网 | WebSocket | 低延迟，双向通信，已有实现 |
| 互联网 | HTTP/REST | 企业友好，易于调试 |
| 实时双向 | WebSocket | 双向通道 |
| NAT穿透 | WebRTC DataChannel | ICE/STUN穿透 |
| 低延迟高吞吐 | QUIC | 0-RTT，UDP多路复用 |
| 音视频Agent | WebRTC | 媒体流支持 |

### 3.2 QUIC概念架构

```
┌──────────────────────────────────────────┐
│            QUIC TransportAdapter          │
│  ┌───────────┐  ┌───────────┐            │
│  │ 0-RTT     │  │ 多路复用   │            │
│  │ 快速重连   │  │ 多stream  │            │
│  └───────────┘  └───────────┘            │
├──────────────────────────────────────────┤
│  aioquic (Python)                         │
│  内置TLS 1.3加密                          │
└──────────────────────────────────────────┘
```

### 3.3 WebRTC概念架构

```
Agent A                              Agent B
┌──────────┐                        ┌──────────┐
│ WebRTC    │  SDP协商               │ WebRTC    │
│ Peer      │ ←──STUN/TURN──→       │ Peer      │
│ └──┬──────┘                        └──────┬───┘
    │  DataChannel                         │
    │  (双向结构化数据)                    │
    │◄────────────────────────────────────►│
    │                                      │
    │  MediaStream (可选，音视频)           │
    │◄────────────────────────────────────►│
```

### 3.4 接口骨架

```python
class QUICTransportAdapter(TransportBase):
    """QUIC传输适配器（概念设计，暂不实现）"""
    def connect(self) -> None: ...      # 0-RTT握手
    def send(self, message: bytes) -> dict: ...
    def receive(self, timeout: float = 30.0) -> dict | None: ...
    def close(self) -> None: ...


class WebRTCAdapter(TransportBase):
    """WebRTC传输适配器（概念设计，暂不实现）"""
    def connect(self, offer: str) -> str: ...  # SDP协商
    def send(self, message: bytes) -> dict: ...
    def receive(self) -> dict | None: ...
    def close(self) -> None: ...
```

## 4. 实现前置条件

| 前置 | 状态 | 说明 |
|------|------|------|
| 有明确的高延迟/NAT场景需求 | ❌ | 当前无此需求 |
| Python QUIC库成熟度 | ❌ | aioquic维护不足 |
| 同步/异步决策 | ❌ | QUIC/WebRTC都是async |

## 5. 模块位置（预留）

```
python/src/sip_protocol/
├── transport/
│   ├── quic_adapter.py     # QUICTransportAdapter（待实现）
│   └── webrtc_adapter.py   # WebRTCAdapter（待实现）
```
