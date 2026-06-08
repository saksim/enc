# 跨介质加密传输施工落地指南（GPT-5.5 执行版）

> 目标版本：v1.0 施工蓝图  
> 文档状态：后续 GPT-5.5 施工的唯一主线指引  
> 项目根目录：`D:\Download\gaming\new_program\data_helper\6_so_enc`  
> 当前施工文档：`docs/current/cross_media_encrypted_transport_implementation_guide.md`  
> 上一版原文备份：`docs/archive/cross_media_encrypted_transport_implementation_guide.pre_opt_*.md`

---

## 0. 给后续 GPT-5.5 的执行总令

本轮施工只解决一个产品目标：

```text
任意数据 bytes
  -> 加密信封字符串 SOX1
  -> 可拍摄图片
  -> 手机拍照/截图/扫描
  -> 恢复 SOX1 字符串
  -> 用正确密钥解密
  -> 原始数据 bytes
```

不要继续扩展 release、promotion、GitHub evidence、平台发布治理、证据归档平台。那些能力可以保留，但不是当前卡点。

后续 GPT-5.5 必须按以下顺序施工：

1. **P0-S0：CLI 入口解耦**：`python soenc.py transport --help` 与 `python soenc.py cm --help` 必须能在最小跨介质依赖下启动。
2. **P0-S1：SOX1 通用加密信封**：实现 `bytes <-> SOX1 string`，严禁把密钥嵌入信封或图片。
3. **P0-S2：QR 分片视觉传输**：实现 `SOX1 string <-> QR pages <-> photos <-> SOX1 string`。
4. **P0-S3：send/receive 高层命令**：把普通用户路径收敛到 2 条命令。
5. **P0-S4：保留并修复旧 OCR/sidecar manifest-less 缺陷**：不得让旧能力文档声称可用但实际不可闭环。
6. **P0-S5：端到端验收脚本与测试**：以 SHA256 完全一致作为最终准入。

每一步只允许修改与该步骤相关的文件。若某一步失败，回到最早不确定点，不要横向扩展。

---

## 1. 目标、非目标与验收口径

### 1.1 真实目标

面向“密闭环境向外界传递任意小型数据”的实际操作链路：

```text
密闭环境内：
  secret.bin
    -> soenc.py cm encrypt/send
    -> send_pages/*.png

跨介质动作：
  打印 / 屏幕显示 / 手机拍照 / 截图 / 扫描

外界环境内：
  phone_photos/*
    -> soenc.py cm scan/receive
    -> restored.bin
```

### 1.2 P0 必须满足的验收标准

1. **正确性**：`sha256(restored.bin) == sha256(secret.bin)`。
2. **保密性**：图片、SOX1 字符串、manifest、scan report 中不得包含明文、原始 key、key shards、可直接恢复明文的材料。
3. **完整性**：任意篡改 SOX1、QR chunk、图片内容或分片顺序，必须导致扫描失败、CRC 失败、GCM tag 校验失败或最终 SHA 校验失败。
4. **自包含传输**：外界只拿到照片也能恢复 SOX1；manifest 只能作为调试辅助，不得作为 P0 恢复必需品。
5. **易用性**：普通操作者最多使用 2 条主命令：`send` 与 `receive`。
6. **失败可操作**：缺页、坏页、CRC 错误时必须输出 retake plan，明确需要重拍哪一页。
7. **最小依赖**：跨介质命令不得被 protect/build/release 的依赖污染。

### 1.3 明确非目标

P0 不做：

- 公钥加密完整产品化。
- 大文件无限容量传输。
- 一页多 QR 的排版优化。
- 证据链平台、发布审批、GitHub release proof。
- 自动证明目标是否“本地/外部”。本项目只关心 sandbox 内的工程闭环。

---

## 2. 当前仓库事实与可复用资产

### 2.1 关键文件

```text
soenc.py                                      # 仓库统一 CLI wrapper
enc2sop/cli.py                               # 当前统一 CLI；顶层 import 偏重
qrcode_helper.py                             # 旧 airgap/text/image transport 主入口
enc2sop/transport/cli.py                     # 旧 transport CLI parser
enc2sop/transport/protocol.py                # CRC、SHA、payload alphabet、CFG parser
enc2sop/transport/render.py                  # 旧文本页/sidecar 渲染
enc2sop/transport/ocr_embedded.py            # 旧 embedded metadata OCR
enc2sop/transport/parser.py                  # OCR 文本解析、缺片、冲突、parity 思路
enc2sop/transport/recover.py                 # recover/analyze/report/retake 思路
enc2sop/transport/certify.py                 # 证据链、真实拍摄、校正实验工具
scripts/real_capture_text_transport.py       # 旧真实拍摄实验脚本
```

### 2.2 当前依赖事实

在当前本机环境中观察到：

```text
Crypto        可用
cryptography  可用
cv2           可用，且有 QRCodeDetector 与 QRCodeEncoder
PIL           可用
qrcode        不可用
pyzbar        不可用
```

因此 P0 推荐：

- **QR 生成**：优先使用 OpenCV `cv2.QRCodeEncoder_create()`；若不可用，再考虑 Pillow 手绘或可选 `qrcode` 包。
- **QR 扫描**：优先使用 OpenCV `cv2.QRCodeDetector().detectAndDecodeMulti()`，再 fallback 到单图多预处理重试。
- **加密**：优先使用标准库 + `cryptography` 或已有 `Crypto`。为了跨环境稳定，建议在新模块内做轻量 crypto backend 选择，不要顶层依赖旧 `encryption_helper.py`。

### 2.3 当前核心问题

1. `enc2sop/cli.py` 顶层导入 `encryption_helper` 与 promotion 模块，导致 transport/cm 入口容易被非本任务依赖拖死。
2. 旧加密主要面向 Python 代码保护，不是通用数据信封。
3. `enc2sop/keys/local.py` 的 local-embedded 思路不能用于真实保密传输，因为密钥随 artifact 一起带出。
4. 旧 OCR/sidecar 在 manifest-less + `ocr-safe-human-correctable-v1` + parity 场景下存在元数据不完整风险。
5. 真手机照片的旋转、透视、裁切、反光问题还没有进入简单主链路。

---

## 3. 目标架构：两层一接口

后续施工必须把系统收敛为两个互相解耦的层：

```text
┌─────────────────────────────────────────────────────────────┐
│ A. Crypto Envelope 层                                        │
│    输入/输出：bytes <-> SOX1 ASCII string                    │
│    责任：压缩、加密、认证、密钥派生、信封解析、完整性校验       │
│    禁止：关心图片、OCR、QR、证据链、发布治理                   │
└───────────────────────┬─────────────────────────────────────┘
                        │ 唯一接口：ASCII string（SOX1）
┌───────────────────────▼─────────────────────────────────────┐
│ B. Visual Transport 层                                       │
│    输入/输出：SOX1 string <-> images/photos <-> SOX1 string  │
│    责任：分片、QR 渲染、扫描、重组、CRC、retake plan           │
│    禁止：解密明文、读取密钥、判断业务数据含义                 │
└─────────────────────────────────────────────────────────────┘
```

### 3.1 命令形态

底层调试命令：

```bash
python soenc.py cm encrypt --input secret.bin --key-file key.bin --out-string secret.sox1
python soenc.py cm render  --input-string secret.sox1 --output-dir pages --mode qr
python soenc.py cm scan    --image-input phone_photos --out-string recovered.sox1
python soenc.py cm decrypt --input-string recovered.sox1 --key-file key.bin --output restored.bin
```

普通用户主命令：

```bash
python soenc.py cm send \
  --input secret.bin \
  --key-file key.bin \
  --output-dir send_pages \
  --mode qr

python soenc.py cm receive \
  --image-input phone_photos \
  --key-file key.bin \
  --output restored.bin \
  --work-dir receive_work
```

---

## 4. 目录与模块规划

新增目录：

```text
enc2sop/crossmedia/
  __init__.py
  cli.py                 # cm 子命令 parser 与 dispatch
  crypto_envelope.py     # SOX1 信封
  key_material.py        # key-file/passphrase 读取与派生
  qr_transport.py        # QR 分片、渲染、重组
  image_scan.py          # OpenCV/PIL 图片读取、预处理、QR 扫描
  reports.py             # scan/decrypt/send/receive report 写入
  errors.py              # 稳定错误类型与 exit code
```

新增测试：

```text
tests/test_crossmedia_crypto_envelope.py
tests/test_crossmedia_qr_transport.py
tests/test_crossmedia_cli.py
tests/test_crossmedia_e2e.py
```

新增脚本：

```text
scripts/crossmedia_smoke.ps1
scripts/crossmedia_smoke.sh
scripts/simulate_capture_distortions.py
requirements-crossmedia.txt
```

> 说明：P0 可先只实现 Windows PowerShell smoke；Linux shell 可在后续补齐，但测试必须跨平台路径安全。

---

## 5. P0-S0：CLI 入口解耦

### 5.1 目标

以下命令必须在不触发 protect/build/release 重依赖的情况下启动：

```bash
python soenc.py transport --help
python soenc.py cm --help
```

### 5.2 允许修改

```text
enc2sop/cli.py
enc2sop/crossmedia/*
soenc.py（仅在必要时轻微修改）
requirements-crossmedia.txt
```

### 5.3 禁止修改

```text
enc2sop/promotion_*.py
scripts/github_release_promotion_evidence.sh
.github/workflows/release_promotion.yml
release/promotion/GitHub evidence 相关测试的大规模重写
```

### 5.4 施工要求

`enc2sop/cli.py` 当前顶层 import 太重，必须改成 lazy import：

- 顶层只保留标准库、`plugin_registry` 如确有必要、轻量类型。
- `encryption_helper` 只能在 `_run_protect/_run_build/_run_package/_run_verify/_run_release/...` 内部按需导入。
- `promotion_*` 只能在对应 release/promotion 子命令内部按需导入。
- 新增 `_run_cross_media(args)`，内部导入 `enc2sop.crossmedia.cli`。
- 现有 `transport` 子命令也不得因为 `cm` 或 protect 依赖失败。

### 5.5 验收

```bash
python soenc.py --help
python soenc.py transport --help
python soenc.py cm --help
python -m enc2sop cm --help
```

全部返回 exit code 0，且不出现：

```text
ModuleNotFoundError: Crypto
ModuleNotFoundError: qrcode
ModuleNotFoundError: pyzbar
```

---

## 6. P0-S1：SOX1 通用加密信封

### 6.1 信封目标

把任意 bytes 加密成稳定 ASCII 字符串：

```text
bytes -> zlib compress -> AES-256-GCM -> canonical JSON -> base64url -> SOX1.<payload>
```

反向：

```text
SOX1.<payload> -> JSON -> AES-256-GCM verify/decrypt -> zlib decompress -> bytes
```

### 6.2 字符串格式

外层：

```text
SOX1.<base64url_no_padding(canonical_json_utf8)>
```

canonical JSON 要求：

- UTF-8。
- `sort_keys=True`。
- `separators=(",", ":")`。
- 不包含不稳定空白。
- 字段缺失必须 fail closed。

建议 JSON：

```json
{
  "schema": "enc2sop-cross-media-envelope/v1",
  "version": 1,
  "created_at_utc": "2026-06-08T00:00:00Z",
  "content": {
    "name": "optional.bin",
    "original_size": 123,
    "plaintext_sha256": "..."
  },
  "compression": {
    "algorithm": "zlib",
    "enabled": true,
    "compressed_size": 100
  },
  "crypto": {
    "algorithm": "AES-256-GCM",
    "key_mode": "key-file",
    "kdf": null,
    "nonce_b64u": "...",
    "aad_b64u": "...",
    "ciphertext_b64u": "...",
    "tag_b64u": "..."
  }
}
```

### 6.3 AAD 规则

AES-GCM AAD 必须绑定不可被静默篡改的上下文。推荐 AAD 内容：

```json
{
  "schema": "enc2sop-cross-media-envelope/v1",
  "version": 1,
  "compression_algorithm": "zlib",
  "content_name": "optional.bin",
  "original_size": 123,
  "plaintext_sha256": "..."
}
```

AAD 本身可进入 JSON，但 decrypt 时必须重新 canonicalize 后参与 GCM 校验。

### 6.4 密钥模式

P0 支持两种真实模式：

```text
--key-file key.bin
--passphrase
```

`--key-file` 规则：

- 推荐原始 32 bytes。
- 可接受 hex/base64url/base64 文本，但要明确解析规则。
- 解析后必须正好 32 bytes，否则失败。

`--passphrase` 规则：

- 不允许在命令行明文传入 passphrase。
- 从交互式 prompt 或环境变量读取；若用环境变量，变量名必须显式，如 `SOENC_CM_PASSPHRASE`。
- KDF 使用 `scrypt(n=32768, r=8, p=1, key_len=32)` 或 `Argon2id`（若依赖稳定）。P0 推荐 scrypt，因为标准库 `hashlib.scrypt` 可用。
- salt 必须随机生成并写入信封。

禁止：

- 默认使用 `local-embedded`。
- 在 SOX1、QR payload、manifest、report 中写入 key 或 key shards。
- 为了“易用”自动生成并随图携带解密 key。

开发测试如确需嵌入 key，必须使用显式危险开关：

```text
--insecure-embed-key-for-test-only
```

并且：

- 命令名带 `insecure`。
- stderr 打印醒目 warning。
- 测试不得把它作为保密验收。
- 文档不得推荐给用户。

### 6.5 API 建议

`enc2sop/crossmedia/crypto_envelope.py`：

```python
def encrypt_bytes_to_sox1(
    plaintext: bytes,
    *,
    key: bytes,
    name: str | None = None,
    created_at_utc: str | None = None,
    compress: bool = True,
) -> str: ...


def decrypt_sox1_to_bytes(
    sox1: str,
    *,
    key: bytes,
) -> tuple[bytes, dict]: ...
```

`key_material.py`：

```python
def load_key_file(path: Path) -> bytes: ...
def derive_key_from_passphrase(passphrase: str, salt: bytes, *, n: int, r: int, p: int) -> bytes: ...
def generate_key_file(path: Path, *, overwrite: bool = False) -> Path: ...
```

### 6.6 CLI

```bash
python soenc.py cm keygen --key-file key.bin

python soenc.py cm encrypt \
  --input secret.bin \
  --key-file key.bin \
  --out-string secret.sox1

python soenc.py cm decrypt \
  --input-string secret.sox1 \
  --key-file key.bin \
  --output restored.bin
```

`--input-string` 应同时支持：

- 文件路径。
- 直接传入 `SOX1....` 字符串（P0 可选，但如果实现需避免 shell 长度问题）。

推荐明确参数：

```text
--input-string FILE_OR_LITERAL
--input-string-file FILE
--out-string FILE
```

### 6.7 测试清单

`tests/test_crossmedia_crypto_envelope.py`：

```text
test_encrypt_decrypt_roundtrip_key_file
test_encrypt_decrypt_roundtrip_passphrase
test_decrypt_fails_with_wrong_key
test_decrypt_fails_after_ciphertext_tamper
test_decrypt_fails_after_aad_tamper
test_envelope_does_not_embed_key_material
test_binary_file_roundtrip
test_rejects_bad_sox1_prefix
test_rejects_unknown_schema_version
test_key_file_requires_32_bytes_after_decoding
```

---

## 7. P0-S2：QR 分片视觉传输

### 7.1 目标

实现：

```text
SOX1 string -> QR pages/*.png -> phone photos/images -> recovered SOX1 string
```

P0 不再把 OCR 文本页作为主路径；旧 OCR/sidecar 保留为 fallback/实验工具。

### 7.2 分片格式

每个 QR payload 使用短 ASCII，格式固定：

```text
SOX1QR|v=1|id=<artifact_id>|i=<chunk_index>|n=<chunk_total>|sha=<full_sha256_16>|crc=<chunk_crc16>|data=<chunk>
```

字段规则：

| 字段 | 说明 |
|---|---|
| `SOX1QR` | magic，必须严格匹配 |
| `v` | QR transport schema version，P0 固定 `1` |
| `id` | 完整 SOX1 字符串 SHA256 前 12 或 16 hex |
| `i` | 分片序号，从 0 开始 |
| `n` | 总分片数 |
| `sha` | 完整 SOX1 字符串 SHA256 前 16 或 32 hex |
| `crc` | 当前 chunk data 的 CRC16 hex，复用 `enc2sop.transport.protocol.crc16_hex()` |
| `data` | SOX1 字符串的 ASCII 分片 |

P0 chunk 直接切 SOX1 原始 ASCII 字符串即可。因为 SOX1 外层已经是安全 ASCII，不需要再次 base64。

### 7.3 分片大小

推荐默认：

```text
--chunk-chars 700
```

可配置范围：

```text
200 <= chunk_chars <= 1200
```

理由：

- chunk 太大，QR 版本升高，手机拍摄鲁棒性下降。
- chunk 太小，页数过多，人工操作成本高。
- P0 先保守，后续通过 smoke/capture 数据调优。

### 7.4 QR 生成策略

优先使用 OpenCV：

```python
encoder = cv2.QRCodeEncoder_create(params)
img = encoder.encode(payload)
```

若当前 OpenCV Python 绑定的 encoder 参数不稳定，P0 可使用：

- OpenCV 生成二维码矩阵后转 Pillow PNG。
- 或实现一个可选 `qrcode` backend，但不得把它变成 help/import 必需依赖。

渲染要求：

```text
pages/
  page_0001.png
  page_0002.png
  ...
  manifest.json         # 辅助调试，不是恢复必需
  instructions.md       # 操作提示
```

每张页面必须包含：

- 单个 QR code。
- 清晰标题：`SOX1QR <id> page X / N`。
- 操作提示：保持完整边框、避免反光、逐张拍摄。
- 足够 quiet zone。
- QR 最短边建议不低于 800 px。

P0 一页一个 QR；P1 再做一页多 QR。

### 7.5 QR 扫描策略

优先顺序：

```text
1. EXIF 自动旋转 / ImageOps.exif_transpose
2. OpenCV QRCodeDetector.detectAndDecodeMulti
3. OpenCV QRCodeDetector.detectAndDecode
4. 多尺度重试：0.75x / 1.0x / 1.5x / 2.0x
5. 轻量预处理：灰度、阈值、锐化、轻微去噪
```

P0 不强制实现完整四点透视矫正，但必须把失败原因记录进 report。若 QR detector 返回 points，可在 P1 增强透视重试。

### 7.6 重组规则

扫描到 payload 后：

1. parse magic/version。
2. 按 `artifact_id` 分组。
3. 校验 `i/n` 范围。
4. 校验 chunk CRC。
5. 重复 chunk 内容一致则接受；内容冲突则记录 conflict 并失败。
6. `0..n-1` 全部存在后按序拼接。
7. 计算完整 SOX1 SHA256，与 `sha`/`id` 对比。
8. 输出 recovered SOX1。

混入其他批次 QR 时：

- 默认选择扫描到 chunk 数最多且能通过完整校验的 artifact。
- 若多个 artifact 都完整，失败并要求用户指定 `--artifact-id`。
- 不得静默拼接不同 artifact。

### 7.7 scan_report.json

每次 `cm scan` 与 `cm receive` 必须写报告：

```json
{
  "schema": "enc2sop-cross-media-scan-report/v1",
  "success": false,
  "artifact_id": "abcd1234ef56",
  "image_count": 10,
  "chunks_total": 12,
  "chunks_found": 10,
  "duplicates": 2,
  "missing_chunks": [3, 7],
  "retake_pages": [4, 8],
  "bad_images": [
    {
      "path": "IMG_1003.jpg",
      "reason": "qr_not_found_or_crc_failed",
      "suggestion": "retake page 4 closer, keep full border, avoid glare"
    }
  ]
}
```

成功时：

```json
{
  "schema": "enc2sop-cross-media-scan-report/v1",
  "success": true,
  "artifact_id": "abcd1234ef56",
  "chunks_total": 12,
  "chunks_found": 12,
  "duplicates": 3,
  "missing_chunks": [],
  "string_sha256": "...",
  "out_string": "recovered.sox1"
}
```

### 7.8 CLI

```bash
python soenc.py cm render \
  --input-string secret.sox1 \
  --output-dir pages \
  --mode qr \
  --chunk-chars 700

python soenc.py cm scan \
  --image-input phone_photos \
  --out-string recovered.sox1 \
  --work-dir scan_work
```

### 7.9 测试清单

`tests/test_crossmedia_qr_transport.py`：

```text
test_split_join_roundtrip
test_qr_payload_parse_rejects_bad_magic
test_qr_payload_crc_tamper_fails
test_render_scan_roundtrip_png
test_scan_accepts_duplicate_images
test_scan_reports_missing_chunks_with_retake_pages
test_scan_rejects_conflicting_duplicate_chunk
test_scan_rejects_mixed_artifact_ids_when_ambiguous
test_scan_jpeg_roundtrip
test_scan_rotated_image_roundtrip
```

如 CI 环境缺少 OpenCV QR encoder，可把纯分片/parse/report 测试保持必跑，把真实 QR 图像测试用 `skipUnless(cv2_has_qr)` 标记，但本机 smoke 必须跑通。

---

## 8. P0-S3：send/receive 高层命令

### 8.1 send

命令：

```bash
python soenc.py cm send \
  --input secret.bin \
  --key-file key.bin \
  --output-dir send_pages \
  --mode qr
```

内部等价：

```text
encrypt -> render
```

输出：

```text
send_pages/
  pages/page_0001.png
  pages/page_0002.png
  payload.sox1              # 默认可写；如担心落盘，支持 --no-debug-sox1
  manifest.json             # 辅助调试；恢复不得依赖它
  instructions.md
  send_report.json
```

`send_report.json` 至少包含：

```json
{
  "schema": "enc2sop-cross-media-send-report/v1",
  "success": true,
  "input_sha256": "...",
  "artifact_id": "...",
  "pages": 12,
  "mode": "qr",
  "output_dir": "..."
}
```

### 8.2 receive

命令：

```bash
python soenc.py cm receive \
  --image-input phone_photos \
  --key-file key.bin \
  --output restored.bin \
  --work-dir receive_work
```

内部等价：

```text
scan -> decrypt
```

输出：

```text
receive_work/
  scan_report.json
  recovered.sox1
  decrypt_report.json
restored.bin
```

`decrypt_report.json` 至少包含：

```json
{
  "schema": "enc2sop-cross-media-decrypt-report/v1",
  "success": true,
  "output_sha256": "...",
  "output_size": 123,
  "content_name": "optional.bin"
}
```

### 8.3 错误码建议

| exit code | 含义 |
|---:|---|
| 0 | 成功 |
| 2 | CLI 参数错误 |
| 10 | 密钥读取/格式错误 |
| 11 | 解密认证失败 |
| 20 | QR 扫描不完整 |
| 21 | QR CRC/冲突失败 |
| 22 | 混入多个 artifact 且无法自动选择 |
| 30 | 文件 IO 错误 |
| 40 | 可选依赖缺失 |

所有失败都必须 stderr 给人类可读摘要，同时 work-dir 写 JSON report。

---

## 9. P0-S4：旧 OCR/sidecar manifest-less 修复

即使 P0 主路径切到 QR，也必须修复旧 sidecar 文档与行为的冲突，避免后续维护者误判。

### 9.1 已知风险

旧命令在如下配置中，带 manifest 可恢复；不带 manifest 时可能因 embedded metadata 不完整导致 hash mismatch：

```bash
python qrcode_helper.py export \
  -i artifact.bin \
  -o pkg \
  --payload-alphabet-profile ocr-safe-human-correctable-v1 \
  --redundancy-copies 2 \
  --parity-group-size 4

python qrcode_helper.py recover-images \
  -i pkg/pages \
  -o restored.bin \
  --backend auto
```

### 9.2 修复要求

`@CFG` 增加短字段，保持 OCR 友好：

```text
@CFG|AT1|CC=32|LP=12|RC=2|IL=1|PG=4|CS=50|RS=42|PF=O1|PM=modular-sum
```

短码映射：

```text
PF=S1 -> safe-base32-v1
PF=O1 -> ocr-safe-human-correctable-v1
PM=xor
PM=modular-sum
```

涉及文件：

```text
enc2sop/transport/protocol.py
enc2sop/transport/ocr_embedded.py
qrcode_helper.py（只做桥接/调用层必要修改）
tests/test_qrcode_helper_sidecar.py
```

具体要求：

1. `parse_cfg_line()` 接受可选 `PF`、`PM`，旧格式继续兼容。
2. `build_inferred_manifest_from_metadata()` 读取 `PF` 并设置 `manifest["payload_alphabet_profile"]`。
3. encoded length 不能固定用 `safe_base32_encoded_length()`，必须按 profile 计算。
4. sidecar decode 必须传入正确 `payload_alphabet_profile`。
5. OCR whitelist 加入新短字段所需字符，但优先使用短码，避免长 profile 名称造成识别风险。
6. `@META` 可新增 `LINES`/`DATA` 字段澄清语义，但旧 `CHUNKS`/`TOTAL` 仍要兼容。

### 9.3 测试

新增或修复：

```text
tests/test_qrcode_helper_sidecar.py::test_manifestless_ocr_safe_sidecar_with_parity_roundtrip
```

验收：

- 使用 `ocr-safe-human-correctable-v1`。
- `redundancy_copies=2`。
- `parity_group_size=4`。
- `recover-images` 不传 manifest。
- 恢复文件 SHA256 等于原始文件。

---

## 10. P0-S5：端到端 smoke 与质量门禁

### 10.1 PowerShell smoke

新增：`scripts/crossmedia_smoke.ps1`

核心流程：

```powershell
$ErrorActionPreference = 'Stop'
$root = Resolve-Path -LiteralPath '.'
$work = Join-Path $root '.tmp_crossmedia_smoke'
if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
New-Item -ItemType Directory -Path $work | Out-Null

python soenc.py cm keygen --key-file "$work/key.bin"
Set-Content -LiteralPath "$work/plain.txt" -Value 'hello cross media encrypted transport' -Encoding UTF8

python soenc.py cm send `
  --input "$work/plain.txt" `
  --key-file "$work/key.bin" `
  --output-dir "$work/send" `
  --mode qr

python scripts/simulate_capture_distortions.py `
  --input "$work/send/pages" `
  --output "$work/photos" `
  --jpeg-quality 85 `
  --rotate-deg 1.0

python soenc.py cm receive `
  --image-input "$work/photos" `
  --key-file "$work/key.bin" `
  --output "$work/restored.txt" `
  --work-dir "$work/receive"

python -c "from pathlib import Path; import hashlib; a=Path(r'$work/plain.txt').read_bytes(); b=Path(r'$work/restored.txt').read_bytes(); assert hashlib.sha256(a).digest()==hashlib.sha256(b).digest()"
Write-Host 'CROSSMEDIA_SMOKE_OK'
```

### 10.2 模拟拍摄脚本

新增：`scripts/simulate_capture_distortions.py`

P0 支持：

```text
--jpeg-quality 85
--rotate-deg 1.0
--scale 0.75
--blur-radius 0.5
```

输出一组 JPEG/PNG 到 photos 目录，用于 scan 测试。

### 10.3 必跑测试

施工完成后至少运行：

```bash
python -m pytest tests/test_crossmedia_crypto_envelope.py
python -m pytest tests/test_crossmedia_qr_transport.py
python -m pytest tests/test_crossmedia_cli.py
python -m pytest tests/test_crossmedia_e2e.py
python -m pytest tests/test_qrcode_helper_sidecar.py -k manifestless_ocr_safe_sidecar_with_parity_roundtrip
```

若时间允许，再跑：

```bash
python -m pytest tests/test_soenc_cli.py tests/test_transport_modules.py tests/test_qrcode_helper_sidecar.py
```

### 10.4 最终准入

最终 PR/变更必须证明：

```text
CROSSMEDIA_SMOKE_OK
wrong key fails
tampered SOX1 fails
missing page reports retake_pages
scan mixed artifact does not silently merge
```

---

## 11. 安全边界与威胁模型

### 11.1 保护对象

保护的是密闭环境内的原始数据 bytes。攻击者可以获得：

- 所有图片。
- 所有 SOX1 字符串。
- 所有 manifest/report/instructions。
- 源码。
- QR 分片顺序与分片内容。

攻击者不应获得：

- `key.bin`。
- passphrase。
- private key（P1 公钥模式时）。

### 11.2 安全保证

P0 使用对称密钥时保证：

- 无 key 无法解密明文。
- 篡改密文或 AAD 导致 GCM tag 校验失败。
- 篡改 QR chunk 导致 CRC 或完整 SOX1 hash 失败。
- 即使 CRC 被伪造，最终 GCM tag 仍会失败。

### 11.3 不保证

P0 不保证：

- 密钥在操作系统上的安全存储。
- 手机相册/云同步不泄露图片。
- 抗主动钓鱼替换 key。
- 抗量子安全。
- 大文件高效传输。

### 11.4 禁止事项

后续 GPT-5.5 不得为了“跑通 demo”做以下事情：

```text
- 把 key 写入 SOX1 JSON。
- 把 key shards 写入 QR/manifest。
- 默认启用 local-embedded。
- 解密失败时 fallback 到明文输出。
- 捕获异常后仍输出 success=true。
- 扫描多个 artifact 时静默拼接。
- 修改测试让失败路径变成 skip。
```

---

## 12. 施工顺序与每步交付物

### Step 1：入口解耦

交付物：

```text
enc2sop/cli.py lazy import 完成
enc2sop/crossmedia/cli.py 最小 help 可用
python soenc.py cm --help 通过
```

完成定义：

```text
transport/cm help 不依赖 Crypto/qrcode/pyzbar/promotion
旧 protect/build/release 命令 parser 不被破坏
```

### Step 2：SOX1 信封

交付物：

```text
crypto_envelope.py
key_material.py
cm keygen/encrypt/decrypt
tests/test_crossmedia_crypto_envelope.py
```

完成定义：

```text
roundtrip 成功
wrong key 失败
tamper 失败
信封不含 key
```

### Step 3：QR transport

交付物：

```text
qr_transport.py
image_scan.py
cm render/scan
tests/test_crossmedia_qr_transport.py
```

完成定义：

```text
PNG 原图 scan 成功
JPEG 模拟图 scan 成功
缺页输出 retake plan
混入其他 artifact 不静默拼接
```

### Step 4：send/receive

交付物：

```text
cm send/receive
send_report.json
scan_report.json
decrypt_report.json
tests/test_crossmedia_e2e.py
```

完成定义：

```text
一条 send + 一条 receive 恢复原文件
sha256 完全一致
失败路径有 JSON report
```

### Step 5：旧 sidecar bug 修复

交付物：

```text
@CFG PF/PM 支持
manifest-less inference 支持 payload profile
test_manifestless_ocr_safe_sidecar_with_parity_roundtrip
```

完成定义：

```text
旧 OCR-safe + parity + no manifest 场景可恢复或给出清晰不可用原因
文档不再声称未实现能力已可用
```

### Step 6：smoke 与文档同步

交付物：

```text
scripts/crossmedia_smoke.ps1
scripts/simulate_capture_distortions.py
README 或 docs/current 补充最终用户命令
```

完成定义：

```text
CROSSMEDIA_SMOKE_OK
测试命令记录在最终回复/变更说明中
```

---

## 13. 推荐实现细节

### 13.1 base64url helper

统一实现，不要散落：

```python
def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def b64u_decode(text: str) -> bytes:
    raw = str(text).encode("ascii")
    raw += b"=" * ((4 - len(raw) % 4) % 4)
    return base64.urlsafe_b64decode(raw)
```

### 13.2 atomic write

输出重要文件使用临时文件 + replace，避免中途失败留下半文件：

```python
tmp = output.with_suffix(output.suffix + ".tmp")
tmp.write_bytes(data)
tmp.replace(output)
```

### 13.3 路径安全

- 不要递归扫描用户目录。
- `--image-input` 只处理显式目录下的图片。
- 支持后缀：`.png .jpg .jpeg .bmp .webp .tif .tiff`。
- report 中路径使用相对 `image-input` 的路径，避免泄露无关本机目录。

### 13.4 大小限制

P0 默认限制：

```text
明文 <= 256 KiB
SOX1 字符串 <= 2 MiB
QR chunks <= 500
```

超过限制时失败并提示 P1 大文件分卷尚未实现。不要让程序生成上千张图导致不可操作。

---

## 14. P1 路线图（P0 完成后再做）

### P1-S1：公钥模式

```bash
python soenc.py cm keygen-public --public public.pem --private private.pem
python soenc.py cm encrypt --input secret.bin --recipient-public-key public.pem --out-string secret.sox1
python soenc.py cm decrypt --input-string secret.sox1 --private-key private.pem --output restored.bin
```

推荐混合加密：

```text
X25519/RSA-OAEP 包装 data key + AES-256-GCM 加密数据
```

### P1-S2：大文件分卷

```text
large.bin
  -> volume_0001.sox1
  -> volume_0002.sox1
  -> ...
```

每卷独立认证，最终 group manifest 校验整文件 SHA256。

### P1-S3：一页多 QR 与重复布局

```text
每页 4/6/8 个 QR
每个 chunk 至少出现 2 次
页脚显示 retake 编号
```

### P1-S4：真实手机拍摄增强

- 自动四点透视矫正。
- 反光/模糊质量评分。
- 拍摄指引图。
- 基于真实 capture corpus 的鲁棒性报告。

### P1-S5：证据链工具降级为实验模式

保留 `certify/archive/status`，但它们不进入普通用户主链路。主链路永远是：

```text
send / receive
```

---

## 15. 最终验收清单

后续 GPT-5.5 完成施工后，必须在最终回复中给出以下证据块：

```text
变更文件：
- enc2sop/cli.py
- enc2sop/crossmedia/...
- tests/test_crossmedia_...
- scripts/crossmedia_smoke.ps1

执行命令：
- python soenc.py cm --help
- python -m pytest tests/test_crossmedia_crypto_envelope.py
- python -m pytest tests/test_crossmedia_qr_transport.py
- python -m pytest tests/test_crossmedia_e2e.py
- powershell -ExecutionPolicy Bypass -File scripts/crossmedia_smoke.ps1

关键结果：
- roundtrip sha256 matched
- wrong key failed
- tamper failed
- missing page retake_pages reported
- CROSSMEDIA_SMOKE_OK
```

如果任何一项失败，不得宣称施工完成。

---

## 16. 一句话结论

当前项目的正确收敛方向不是继续堆发布治理和证据链，而是先把产品主链路做成两个稳定层：

```text
Crypto Envelope：bytes <-> SOX1
Visual Transport：SOX1 <-> QR photos <-> SOX1
```

做到 `send/receive` 两条命令端到端 SHA256 一致，并且错误时能告诉操作者重拍哪一页，才算真正完成“跨介质加密传输”的 P0 落地。
