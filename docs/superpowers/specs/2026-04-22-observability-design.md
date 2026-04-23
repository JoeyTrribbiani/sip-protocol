# OpenTelemetry 可观测性设计文档

> 版本: v1.0
> 日期: 2026-04-22
> 状态: 概念设计
> 关联: M6 (sip-protocol-report.md Section 8.5.2 M6)

## 1. 问题陈述

SIP协议无日志、追踪、监控接口。生产环境需要可观测性来排查问题。

## 2. 设计原则

1. **OpenTelemetry兼容** — 使用OTel标准，不造轮子
2. **零侵入** — 默认关闭，配置开启
3. **分层导出** — 支持stdout（开发）、OTLP（生产）、自定义

## 3. 日志格式

```python
# 使用标准库 logging + JSON formatter，不引入structlog等第三方依赖
import logging
import json


class JSONFormatter(logging.Formatter):
    """结构化JSON日志格式化器"""

    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # 额外字段从record.__dict__获取
        for key in ("trace_id", "agent_id", "recipient_id",
                     "message_type", "message_id", "duration_ms",
                     "status", "error_code"):
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)
        return json.dumps(log_entry, default=str)


logger = logging.getLogger("sip")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(JSONFormatter())
logger.addHandler(handler)

# 结构化日志
logger.info(
    "message_sent",
    extra={
        "trace_id": "trace-xxx",
        "agent_id": "agent-xxx",
        "recipient_id": "agent-yyy",
        "message_type": "task_delegate",
        "message_id": "msg-xxx",
        "duration_ms": 2.5,
        "status": "success",
    },
)
```

## 4. 追踪模型

每个SIP操作（握手、加密、解密、发送）生成一个Span：

```
Trace: conversation-xxx
├── Span: handshake (12ms)
│   ├── Span: dh_exchange (2ms)
│   └── Span: key_derivation (1ms)
├── Span: encrypt_message (0.5ms)
├── Span: send_message (3ms)
├── Span: decrypt_message (0.4ms)
└── Span: rekey (15ms)
```

## 5. 指标

```python
METRICS = {
    # 计数器
    "sip_messages_sent_total": Counter,
    "sip_messages_received_total": Counter,
    "sip_handshakes_total": Counter,
    "sip_rekeys_total": Counter,
    "sip_errors_total": Counter,

    # 直方图
    "sip_message_size_bytes": Histogram,
    "sip_encryption_duration_seconds": Histogram,
    "sip_decryption_duration_seconds": Histogram,

    # 仪表盘
    "sip_active_sessions": Gauge,
    "sip_active_groups": Gauge,
    "sip_pending_messages": Gauge,
}
```

## 6. 配置

```python
@dataclass
class ObservabilityConfig:
    enabled: bool = False                          # 默认关闭
    log_level: str = "INFO"
    exporter: str = "stdout"                       # stdout | otlp | none
    otlp_endpoint: str = "http://localhost:4317"   # OTLP gRPC端点
    trace_sample_rate: float = 0.1                 # 10%采样
    metrics_interval: float = 30.0                 # 指标上报间隔
```

## 7. 实现

```python
class SIPObserver:
    """SIP可观测性管理器"""

    def __init__(self, config: ObservabilityConfig):
        self._config = config
        if config.enabled:
            self._setup_logging()
            self._setup_tracing()
            self._setup_metrics()
        else:
            self._noop()

    def trace(self, operation: str) -> "SIPSpan":
        """开始追踪一个操作"""

    def record_metric(self, name: str, value: float) -> None:
        """记录指标"""

    def record_error(self, error: SIPError, context: dict | None = None) -> None:
        """记录错误"""
```

## 8. 模块位置

```
python/src/sip_protocol/
├── observability/
│   ├── __init__.py
│   ├── config.py       # ObservabilityConfig
│   ├── observer.py     # SIPObserver
│   ├── logging.py      # 结构化日志
│   └── metrics.py      # 指标定义
```
