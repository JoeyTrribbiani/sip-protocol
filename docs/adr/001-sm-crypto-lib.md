# ADR-001：国密（SM 系列）密码原语依赖选型

| | |
|---|---|
| 状态 | Accepted |
| 日期 | 2026-09-12 |
| 背景 | 老徐指令：sip-protocol 增加国密支持（SM 系列中国商用密码标准），套件协商式（EN 国际 / ZH 国密），EN 行为逐位不变 |
| 决策范围 | SM2（密钥交换）/ SM3（哈希/HMAC/HKDF）/ SM4（AEAD）的原语来源 |

## 背景与约束

- 本库是 pip/uv 分发的加密库（依赖越少越好，CI 有 pip-audit）。
- ZH 套件需要：SM2 ECDH（三重 DH 类比）、SM3（哈希/HMAC/HKDF 抽象）、SM4-AEAD（会话消息/文件工件）。
- 红线：EN 套件行为逐位不变；PSK 的 Argon2id 路径不动（固定盐遗留问题另记，不混入本批）。
- 本库为通用分发库，**不宣称商密合规认证**（无 GM 认证诉求，如实记述实现形态）。

## 候选路线与实证结论

### 路线 A：gmssl（PyPI `gmssl` 3.2.2，duanhongyi/py-gmssl，纯 Python，类 BSD 许可）

实测（本仓库 venv，Python 3.11）：

- SM3：`sm3_hash()` 一次性接口，**无增量类**；与 cryptography/OpenSSL SM3 双实现输出一致（交叉验证通过）。
- SM4：**仅 ECB/CBC，无 GCM/CTR**；且 `crypt_ecb` 自带 PKCS7 填充（16B 输入 → 32B 输出），
  直接作为 GCM 底层块原语需剥填充，形态别扭。
- SM2：`CryptSM2` 面向签名/加密；ECDH 只能借私有方法 `_kg`（点乘），API 稳定性无承诺。
- 性能：纯 Python，社区基准约 60KB/s（SM4）；文件工件路径不可用。
- 传递依赖：拖入 `pycryptodomex`（ASN.1 DER 用）——运行时依赖面扩大。

### 路线 B：snowland-smx（社区俗称 "pysmx"；PyPI 上名为 `pysmx` 的包是 SourceMod 游戏插件解析器，与国密无关）

- 纯 Python SM2/SM3/SM4/SM9/ZUC，社区规模与维护度显著弱于 gmssl。
- 同样无 SM4-GCM、同样纯 Python 性能问题、同样需要自建 AEAD 构造。
- 无相对 gmssl 的优势项，排除。

### 路线 C：openssl 路线

- C-1 `cryptography`（pyca，绑定 OpenSSL 3）：**实测可用** —— `hashes.SM3`（35.0.0 起）、
  `algorithms.SM4`（35.0.0 起）、`Cipher(algorithms.SM4, modes.GCM)`（**42.0.0 起**），
  本仓库锁定 50.0.1 全部实测通过：SM4-GCM 往返/防篡改 OK、HKDF-SM3 OK、
  HMAC-SM3（标准库 hmac + 哈希适配器）与 RFC 2104 手工构造一致。
  C 实现（常量时间性、性能）远优于纯 Python。**缺 SM2**（pyca issue #9658，未实现）。
- C-2 `gmssl-python`（GmSSL C 库 ctypes 封装）：功能最全（含 SM4-GCM），
  但要求宿主机预装 GmSSL C 动态库——pip 分发不可自举，部署负担不可接受，排除。

## 决策

**混合路线（以 C-1 为主体）**：

| 原语 | 来源 | 理由 |
|------|------|------|
| SM3 / HMAC-SM3 / HKDF-SM3 | `cryptography`（OpenSSL C） | 既有依赖零新增；C 实现；HKDF 原生支持 `hashes.SM3()` |
| SM4-GCM AEAD | `cryptography`（OpenSSL C，42.0.0 起） | 12B nonce / 16B tag，与 EN 套件 wire 尺寸同构；RFC 8998（TLS_SM4_GCM_SM3）先例；`InvalidTag` 异常与既有解包路径同型 |
| SM2 曲线运算（密钥对 + 原始 ECDH） | **本库自研**（`crypto/sm2.py`，GM/T 0003.5 推荐曲线 sm2p256v1，纯标准库整数运算） | pyca 无 SM2；gmssl `_kg` 为私有 API；自研范围有界（密钥生成 + [d]P 点乘，无签名/加密），参数取自标准，测试与 gmssl 双向交叉验证 |

- 依赖变更：`cryptography>=41.0.0` → **`cryptography>=42.0.0`**（SM4-GCM 下限）；**无新增运行时依赖**。
- `gmssl` 3.2.2 进 **dev 依赖组**，仅用于测试交叉验证（SM2 点乘 / SM3 独立复算），不进运行时。
- 互操作参考实现（`scripts/interop/reference_impl.py`）的 ZH 支持按既有模式：复用 cryptography 的
  SM3/SM4-GCM 原语（与 EN 复用 ChaCha20 同构），协议逻辑（HKDF-SM3、HMAC transcript、SM2 点乘）独立实现
  （SM2 用 Jacobian 坐标独立编写，与主库仿射实现互为第二实现）。

## 后果与如实记述

1. **SM4-GCM 标准化状态**：GB/T 体系内 SM4 的 AEAD 形态无单一强制标准（GB/T 36624 为通用 GCM 构造），
   SM4-GCM 由 RFC 8998（TLS 1.3 商密套件）事实标准化。本库采用 SM4-GCM 并在 SPEC §3/§13 如实标注
   （与上游对 ChaCha20 nonce 长度的诚实标注同一风格）。
2. **SM2 ECDH 形态**：采用原始 ECDH（共享秘密 = [d]P 的 x 坐标）而非 GM/T 0003.3 完整密钥交换
   （后者含显式确认流，与三重 DH 构造不兼容）。身份绑定与认证性由三重 DH + PSK 混入 IKM 提供
   （与 EN 套件同构），SPEC §13 登记。
3. **常量时间性**：`crypto/sm2.py` 纯 Python 非常量时间（gmssl 等纯 Python 实现同等限制）；
   SM3/SM4-GCM 为 OpenSSL C 实现。威胁模型（攻击者不掌握 PSK/私钥、握手有 PSK 绑定 HMAC 兜底）
   下接受，SPEC §12 记述。
4. **无效曲线攻击**：对端公钥做在曲线校验 + 非无穷远点校验后才开始 ECDH。
5. **PSK 拉伸**：两套件统一保留 Argon2id（红线要求 PSK 路径不动；商密体系无内存困难 KDF 等价物，
   替换为 PBKDF2-SM3 反而降低防穷举强度）——SPEC §3 标注为套件无关组件。
6. **性能**：ZH 套件握手含 ~6 次 SM2 点乘（纯 Python，每次约 10ms 量级），会话消息/文件工件为
   C 实现性能与 EN 同级；纯 Python 部分仅握手/Rekey，可接受。
7. 若未来 pyca 落地 SM2（issue #9658），可平滑切换 `crypto/sm2.py` 底层而不动协议层（接口已按
   X25519 鸭子类型对齐）。

## 备选落选原因摘要

- gmssl 全家桶：无 SM4-GCM、ECB 带填充、私有 API、纯 Python 性能（文件工件不可用）、传递依赖 pycryptodomex。
- snowland-smx：维护度弱，无优势项。
- GmSSL C 绑定：宿主机依赖，pip 分发不可自举。
