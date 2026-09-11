// dsh-sip-protocol host 入口 v0.1：零部署纯声明式
// 1. 不守护任何服务进程（对比 dsh-timesfm 的常驻 Python 服务）
// 2. agent tool：sip_encrypt / sip_decrypt 注册进 dsh agent（defineTool + ctx.tools.register）
// 3. 每次调用一次性 spawn Python（SIP_PYTHON，默认 python3.11）执行 sip_protocol.crypto 原语，
//    请求经 stdin 传入（密钥不进 argv，避免进程列表泄漏），响应为 stdout 单行 JSON
// 姿势同 dsh-timesfm v0.2 / dsh-rag-knowledge v0.1（官方 API 实证见 RAG 知识库 "dsh 插件接入标准"）。

import { spawn } from 'node:child_process';
import { defineTool } from '@deepseek-ai/dsh-tools';

export const name = 'dsh-sip-protocol';
export const inject = ['tools'];
export const provide = [];

const PY_BIN = process.env.SIP_PYTHON ?? 'python3.11';

// 一次性 Python 片段：stdin JSON → stdout JSON；错误以 ok:false 返回（退出码恒 0，输出可预期）
const PY_SNIPPET = `
import sys, json
try:
    from sip_protocol.crypto.xchacha20_poly1305 import (
        encrypt_xchacha20_poly1305,
        decrypt_xchacha20_poly1305,
        generate_nonce,
    )
    req = json.loads(sys.stdin.read())
    op = req.get("op")
    if op == "encrypt":
        key = bytes.fromhex(req["key_hex"])
        nonce = generate_nonce()
        ct, tag = encrypt_xchacha20_poly1305(key, req["plaintext"].encode("utf-8"), nonce)
        out = {"ok": True, "algorithm": "XChaCha20-Poly1305 AEAD",
               "nonce_hex": nonce.hex(), "ciphertext_hex": ct.hex(), "auth_tag_hex": tag.hex()}
    elif op == "decrypt":
        key = bytes.fromhex(req["key_hex"])
        pt = decrypt_xchacha20_poly1305(
            key,
            bytes.fromhex(req["ciphertext_hex"]),
            bytes.fromhex(req["nonce_hex"]),
            bytes.fromhex(req["auth_tag_hex"]),
        )
        out = {"ok": True, "plaintext": pt.decode("utf-8")}
    else:
        out = {"ok": False, "error": "unknown op: %r" % (op,)}
except Exception as e:  # noqa: BLE001 - 统一转 JSON 错误返回
    out = {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}
print(json.dumps(out, ensure_ascii=False))
`;

/** 一次性调用 sip_protocol.crypto 原语。 */
function pySip(payload, timeoutMs = 15_000) {
  return new Promise((resolve) => {
    const child = spawn(PY_BIN, ['-c', PY_SNIPPET], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.on('error', (e) => {
      clearTimeout(timer);
      resolve({ ok: false, error: `spawn ${PY_BIN} 失败: ${e.message}（可用 SIP_PYTHON 指定解释器）` });
    });
    child.stdout.on('data', (c) => (stdout += c));
    child.stderr.on('data', (c) => (stderr += c));
    child.on('close', (code) => {
      clearTimeout(timer);
      try {
        resolve(JSON.parse(stdout.trim().split('\n').pop()));
      } catch {
        resolve({
          ok: false,
          error: `python 退出码 ${code}，输出不可解析（需 pip install -e python/ 使 sip_protocol 可导入）: ${stderr.trim() || stdout.trim()}`,
        });
      }
    });
    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  });
}

const ENCRYPT_OUT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    ok: { type: 'boolean' },
    algorithm: { type: 'string' },
    nonce_hex: { type: 'string', description: '12 字节 nonce（hex）' },
    ciphertext_hex: { type: 'string', description: '密文（hex）' },
    auth_tag_hex: { type: 'string', description: '16 字节认证标签（hex）' },
    error: { type: 'string' },
  },
};

const DECRYPT_OUT_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  properties: {
    ok: { type: 'boolean' },
    plaintext: { type: 'string' },
    error: { type: 'string', description: '认证失败/参数错误时给出原因' },
  },
};

export function apply(ctx, config) {
  const logger = ctx?.logger ?? console;
  logger?.info?.('[dsh-sip-protocol] 注册 sip_encrypt / sip_decrypt（零部署，按需一次性调用 Python）');

  ctx.effect(() => {
    ctx.tools.register(
      defineTool({
        name: 'sip_encrypt',
        description:
          'Encrypt UTF-8 text with SIP XChaCha20-Poly1305 AEAD (local, one-shot). Pass a 32-byte hex key and plaintext; get nonce/ciphertext/auth_tag hex fields. Ship all three fields together with the key designation to the decrypt side. For full handshake/rekey channels use the SIP MCP server instead.',
        parameters: {
          key_hex: {
            type: 'string',
            required: true,
            description: '32 字节密钥（64 个 hex 字符）',
          },
          plaintext: {
            type: 'string',
            required: true,
            description: '要加密的 UTF-8 明文',
          },
        },
        output: { schema: ENCRYPT_OUT_SCHEMA },
        execute: async (args) =>
          pySip({ op: 'encrypt', key_hex: args.key_hex, plaintext: args.plaintext }),
      }),
    );

    ctx.tools.register(
      defineTool({
        name: 'sip_decrypt',
        description:
          'Decrypt SIP XChaCha20-Poly1305 AEAD ciphertext (local, one-shot). Pass key/ciphertext/nonce/auth_tag hex fields from sip_encrypt; returns plaintext, or an auth error if the tag does not match (tampered or wrong key).',
        parameters: {
          key_hex: {
            type: 'string',
            required: true,
            description: '32 字节密钥（64 个 hex 字符）',
          },
          ciphertext_hex: {
            type: 'string',
            required: true,
            description: 'sip_encrypt 返回的密文（hex）',
          },
          nonce_hex: {
            type: 'string',
            required: true,
            description: 'sip_encrypt 返回的 nonce（hex）',
          },
          auth_tag_hex: {
            type: 'string',
            required: true,
            description: 'sip_encrypt 返回的认证标签（hex）',
          },
        },
        output: { schema: DECRYPT_OUT_SCHEMA },
        execute: async (args) =>
          pySip({
            op: 'decrypt',
            key_hex: args.key_hex,
            ciphertext_hex: args.ciphertext_hex,
            nonce_hex: args.nonce_hex,
            auth_tag_hex: args.auth_tag_hex,
          }),
      }),
    );
    return () => {};
  }, 'dsh-sip-protocol: agent tools');
}
