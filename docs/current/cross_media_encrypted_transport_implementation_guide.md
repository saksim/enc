# 跨介质加密解密传送：现状诊断与后续 GPT5.5 施工文档

> 目标版本：V0.1 施工指引  
> 分析对象：`6_so_enc.rar` 解包后的代码包  
> 唯一目标：让任意数据在密闭环境内被加密成字符串，再被渲染成图片；外界用手机拍摄图片后，使用同一套代码恢复字符串并解密出原始数据。  
> 明确排除：不要继续围绕 release / promotion / GitHub evidence / 平台发版治理扩展；这些不是当前卡点。

---

## 1. 最终目标的工程化定义

用户真正要的不是“加密平台发布治理”，而是一条可被普通操作者执行的跨介质链路：

```text
密闭环境内：
原始数据 bytes
  -> 加密信封 encrypted envelope
  -> 稳定 ASCII 字符串 SOX1.xxx
  -> 一张或多张可拍摄图片 pages/*.png

跨介质动作：
手机拍照 / 扫描 / 截图 / 传图

外界环境内：
照片 images/*
  -> 自动识别/纠偏/解码
  -> 还原 SOX1.xxx 字符串
  -> 使用同一套代码 + 正确密钥解密
  -> 原始数据 bytes
```

验收标准必须是端到端的：

1. **正确性**：恢复文件与原文件 SHA256 完全一致。
2. **保密性**：图片、字符串、manifest 中不得携带可直接解密的密钥。
3. **完整性**：任意一张图片、任意一个字符、任意一个分片被篡改，都必须解密失败或校验失败。
4. **跨介质鲁棒性**：清晰手机照片、轻微旋转、轻微透视、JPEG 压缩、轻微模糊、缩放后仍可恢复，失败时给出明确 retake plan。
5. **自包含性**：外界不应必须拿到额外 manifest 文件；如果需要 manifest，它也必须被编码进图片链路。
6. **易用性**：操作者只需要 4 个命令以内完成：加密、渲染、扫描、解密。

---

## 2. 当前代码包与目标的关系

### 2.1 当前代码里已经有用的部分

与目标强相关的文件：

```text
qrcode_helper.py                         # 旧的空气隔离/图片传输主入口
enc2sop/transport/protocol.py            # 编码、CRC、OCR normalization、payload profile
enc2sop/transport/render.py              # 文本页 + 右侧 binary sidecar 渲染
enc2sop/transport/ocr_runtime.py         # sidecar / tesseract / easyocr / external OCR 编排
enc2sop/transport/ocr_embedded.py        # 无 manifest 时从图片 OCR 读取 embedded metadata
enc2sop/transport/parser.py              # OCR 文本解析、纠错、parity 恢复
enc2sop/transport/recover.py             # verify/analyze/recover 实现
enc2sop/transport/certify.py             # 可靠性证据、capture corpus、物理扫描/相机证据链
scripts/real_capture_text_transport.py   # “文本加密 -> 图片 -> 真实捕获 -> 解密”的试验脚本
```

当前传输层不是标准 QR code。`qrcode_helper.py` 名字像 QR，但实际核心是：

```text
zlib 压缩 bytes
  -> safe-base32 或 ocr-safe alphabet
  -> 分片文本行
  -> 每行 CRC
  -> 可选重复/交织/parity
  -> PNG 页面
  -> 右侧 binary sidecar 小黑块
  -> OCR/sidecar 恢复
  -> SHA256 校验
```

这条链路在“生成 PNG 原图”场景下已经能跑通。

### 2.2 我实测到的结果

在当前环境中直接用 `qrcode_helper.py` 做最小闭环，结果如下：

```text
artifact.bin
  -> qrcode_helper.py export
  -> pages_txt recover：成功，cmp 一致
  -> recover-images + manifest + backend auto：成功，选择 sidecar，cmp 一致
  -> recover-images + manifest + backend tesseract：成功，cmp 一致
```

另外做了几类轻量图片扰动：

```text
JPEG q85：成功
轻微 blur：成功
低对比度：成功
50% 缩放再放大：成功
轻微旋转/裁剪：出现超时或失败风险
```

这说明：

1. 当前核心不是完全不可用；生成图、清晰图、部分压缩/模糊场景能恢复。
2. 真正的手机拍摄风险主要在 **透视、旋转、裁剪、页面定位**，而不是加密本身。
3. 现有代码已经有很多证据链功能，但普通端到端使用体验还没有收敛。

### 2.3 当前直接阻塞点

#### 阻塞 1：统一入口 `soenc.py transport ...` 被非传输依赖拖死

执行：

```bash
python3 soenc.py transport --help
```

当前会失败：

```text
ModuleNotFoundError: No module named 'Crypto'
```

原因是 `enc2sop/cli.py` 顶层直接 `import encryption_helper`，而 `encryption_helper.py` 又依赖 `Crypto.Cipher.AES`。即使用户只想用 `transport`，也会被主平台加密依赖阻塞。

这必须作为 P0 修复：传输 CLI 入口必须可独立启动，不能被 protect/build/release 的依赖污染。

#### 阻塞 2：当前“加密”更偏 Python 代码保护，不是通用数据加密信封

`encryption_helper.encrypt_snippet()` 使用 AES-GCM，这是可用的密码学原语；但它的上下文是“保护 Python 源码片段”，不是“任意数据跨介质传输”。

`scripts/real_capture_text_transport.py` 有一个文本试验包装，但它仍然是试验脚本，不是清晰的产品命令。

当前缺少一个稳定的、与传输层解耦的通用信封：

```text
bytes -> encrypted envelope -> SOX1 字符串
SOX1 字符串 -> envelope -> bytes
```

#### 阻塞 3：`local-embedded` 不能作为真实保密方案

`enc2sop/keys/local.py` 会把 AES key 拆成 XOR shards 后随 artifact 一起保存。它能用于运行时自解密/测试，但如果这个 artifact 被编码到图片并带到外界，密钥也等于一起带出去了。

对“密闭环境 -> 外界”的真实保密目标来说：

```text
图片里绝对不能同时包含密文和可还原明文的密钥。
```

P0 必须改成：

1. `--key-file`：密闭环境和外界预先都有同一把 32-byte key；或
2. `--passphrase`：双方预共享口令，用 KDF 派生 AES key；或
3. P1 再做公钥模式：外界先生成 public key，密闭环境只持 public key，外界用 private key 解密。

#### 阻塞 4：无 manifest 恢复还不可靠，尤其 OCR-safe + redundancy/parity

我用如下配置生成图片：

```text
--payload-alphabet-profile ocr-safe-human-correctable-v1
--redundancy-copies 2
--parity-group-size 4
```

带 manifest 恢复成功；但不带 manifest 直接从图片恢复失败，最终报 compressed sha256 mismatch。

观察到的原因：

1. `@CFG` embedded metadata 当前只包含 `CC/LP/RC/IL/PG/CS/RS`。
2. 它没有记录 `payload_alphabet_profile`。
3. `enc2sop/transport/ocr_embedded.py` 的 `build_inferred_manifest_from_metadata()` 默认按 `safe_base32` 推断编码长度和 sidecar payload profile。
4. 当实际使用 `ocr-safe-human-correctable-v1` 时，无 manifest sidecar 解码会按错误 alphabet 解释 bit payload，得到可成行但内容错误的 payload，最终 hash mismatch。

这对用户最终目标很关键：如果外界只有手机拍到的图片，没有额外 manifest 文件，当前可靠模式并不闭环。

#### 阻塞 5：手机照片的自动透视纠偏没有进入简单 recover-images 主链路

代码里有 `correct-capture-perspective`、capture corpus、真实相机 evidence gate 等能力，但对普通用户来说流程过重。

当前简单命令：

```bash
python qrcode_helper.py recover-images -m manifest -i photos -o restored.bin --backend auto
```

更适合生成图、截图、轻度压缩图。对真实手机拍摄的旋转、透视、裁边，现有流程需要额外人工/证据链步骤，没有形成“自动识别页面 -> 纠偏 -> 解码 -> retake plan”的产品化闭环。

---

## 3. 战略判断：不要继续堆平台治理，先收敛成两个独立层

后续不要再让 GPT5.5 继续沿着 promotion/release/certification 方向扩展。当前目标只需要两个稳定模块：

```text
A. Crypto Envelope 层
   负责：任意 bytes <-> 加密字符串
   不关心图片、不关心 OCR、不关心证据链

B. Visual Transport 层
   负责：字符串 <-> 图片 <-> 手机照片 <-> 字符串
   不关心明文、不关心业务、不关心 Python 代码保护
```

二者之间唯一接口：

```text
ASCII string
```

推荐最终形态：

```text
python soenc.py cm encrypt  --input secret.bin --key-file key.bin --out-string secret.sox1
python soenc.py cm render   --input-string secret.sox1 --output-dir pages --mode qr
python soenc.py cm scan     --image-input phone_photos --out-string recovered.sox1
python soenc.py cm decrypt  --input-string recovered.sox1 --key-file key.bin --output restored.bin
```

其中 `cm` 表示 `cross-media`。

---

## 4. 推荐实现路线

### 总体建议

为了最快解决“手机拍照跨介质传输”，建议 P0 优先做 **QR 分片传输模式**，而不是继续硬扛通用 OCR。

原因：

1. QR 本身就是为相机识别设计的，有定位点、透视识别、纠错能力。
2. 当前 OCR/sidecar 需要额外 manifest、坐标、字体、band 检测，真实手机拍摄会受旋转/透视/裁剪影响。
3. 当前环境已经能看到 `qrcode`、`cv2`、`pyzbar` 类依赖可用；即使后续要显式写入 requirements，也比自研 OCR 坐标系统风险低。
4. 现有 sidecar/OCR 代码可以保留为 fallback 或证据链工具，但不要作为 P0 唯一路径。

P0 的务实路径：

```text
加密字符串 SOX1
  -> 切分成 N 个 chunk
  -> 每个 chunk 一个 QR，或每页多个 QR
  -> 手机拍照
  -> OpenCV/pyzbar decodeMulti
  -> CRC/SHA/序号重组
  -> SOX1
  -> AES-GCM 解密
```

---

## 5. P0 施工任务拆解

### P0-S0：修复 transport / cross-media CLI 可独立启动

#### 目标

用户只运行跨介质命令时，不应因为主平台 `Crypto`、Cython、release 等依赖失败。

#### 修改建议

文件：`enc2sop/cli.py`

当前问题：顶层导入太重：

```python
import encryption_helper
```

改法：

1. 顶层只保留轻量标准库和 plugin registry。
2. 在 `_run_protect/_run_build/_run_package/_run_verify/_run_release` 内部再 lazy import `encryption_helper`。
3. `_run_transport` 或新 `_run_cross_media` 不得 import `encryption_helper`。
4. 新增 `requirements-transport.txt` 或 `requirements-crossmedia.txt`，明确列出最小依赖。

#### 验收命令

```bash
python soenc.py transport --help
python qrcode_helper.py --help
python soenc.py cm --help
```

其中 `soenc.py cm --help` 是后续新增命令。

#### 验收标准

1. 在未安装主平台 protect/build 依赖时，transport/cm help 能启动。
2. 不出现 `ModuleNotFoundError: Crypto`。
3. 不触碰 promotion/release 逻辑。

---

### P0-S1：新增通用加密信封 `SOX1`

#### 目标

把“任意数据加密成字符串”做成稳定能力。

#### 新增模块建议

```text
enc2sop/crossmedia/__init__.py
enc2sop/crossmedia/crypto_envelope.py
enc2sop/crossmedia/cli.py
```

#### 信封格式

字符串外层：

```text
SOX1.<base64url_no_padding(canonical_json)>
```

JSON 内层建议：

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

如果使用 passphrase：

```json
"key_mode": "passphrase-scrypt",
"kdf": {
  "name": "scrypt",
  "salt_b64u": "...",
  "n": 32768,
  "r": 8,
  "p": 1,
  "key_len": 32
}
```

#### 密钥规则

P0 支持两种：

```text
--key-file key.bin       # 必须是 32 bytes，或支持 base64/hex 文本
--passphrase             # 从交互输入或环境变量读取，不写入命令历史
```

禁止默认使用 `local-embedded`。如果为了开发测试允许 `--insecure-embed-key`，必须：

1. 命令名带 `insecure`；
2. 输出 warning；
3. 测试报告不得把它当成真实保密能力。

#### CLI

```bash
python soenc.py cm encrypt \
  --input ./secret.bin \
  --key-file ./key.bin \
  --out-string ./secret.sox1

python soenc.py cm decrypt \
  --input-string ./secret.sox1 \
  --key-file ./key.bin \
  --output ./restored.bin
```

#### 验收测试

1. 明文 roundtrip：`cmp secret.bin restored.bin` 成功。
2. 错 key：必须失败。
3. 篡改 SOX1 任意字符：必须失败。
4. 输出 SOX1 中不能出现明文片段。
5. 输出 SOX1 中不能包含 key 或 key shards。

---

### P0-S2：新增 QR 分片视觉传输模式

#### 目标

解决“字符串 -> 图片 -> 手机拍摄 -> 字符串”的跨介质问题。

#### 新增模块建议

```text
enc2sop/crossmedia/qr_transport.py
enc2sop/crossmedia/image_scan.py
```

#### 分片格式

每个 QR payload 使用短 ASCII：

```text
SOX1QR|v=1|id=<artifact_id>|i=<chunk_index>|n=<chunk_total>|sha=<full_string_sha256_16>|crc=<chunk_crc16>|data=<chunk>
```

说明：

1. `id`：由完整 SOX1 字符串 SHA256 前 10-16 位生成。
2. `i`：从 0 开始。
3. `n`：总分片数。
4. `sha`：完整 SOX1 字符串 SHA256 前 16 或 32 位，用于同批识别。
5. `crc`：单 chunk CRC16 或 CRC32。
6. `data`：base64url-safe 字符串片段。

#### 渲染策略

P0 最简单：一张图片一个 QR。

```text
pages/page_0001.png
pages/page_0002.png
...
```

每张图同时写可读标题：

```text
SOX1QR <id>  page 1 / 12
请保持完整边框，避免反光，逐张拍摄
```

P1 再做一页多个 QR。

#### QR 参数建议

1. error correction：`H` 或至少 `Q`。
2. border：不小于 4 modules。
3. box_size：保证手机拍摄后 QR 最短边不低于 800px。
4. chunk size：保守起步 600-900 chars，根据二维码版本自动估算。
5. 默认 redundancy：每个 chunk 可重复渲染 2 次，或者允许扫描端接受重复照片。

#### 扫描策略

优先顺序：

```text
1. pyzbar / zbar
2. OpenCV QRCodeDetector.detectAndDecodeMulti
3. 单图多尺度/灰度/阈值重试
```

扫描输出：

```json
{
  "success": true,
  "artifact_id": "...",
  "chunks_total": 12,
  "chunks_found": 12,
  "duplicates": 3,
  "missing": [],
  "string_sha256": "...",
  "out_string": "recovered.sox1"
}
```

失败输出必须包含 retake plan：

```json
{
  "success": false,
  "missing_chunks": [3, 7],
  "retake_pages": [4, 8],
  "bad_images": ["IMG_1003.jpg"],
  "reason": "missing_or_crc_failed_chunks"
}
```

#### CLI

```bash
python soenc.py cm render \
  --input-string ./secret.sox1 \
  --output-dir ./pages \
  --mode qr

python soenc.py cm scan \
  --image-input ./phone_photos \
  --out-string ./recovered.sox1
```

#### 验收测试

1. 原始 PNG 扫描恢复 SOX1。
2. JPEG 压缩后恢复 SOX1。
3. 轻微旋转后恢复 SOX1。
4. 轻微透视后恢复 SOX1。
5. 缺一张图时失败，并明确提示缺第几页。
6. 重复拍同一页时不影响恢复。
7. 混入其他批次 QR 时自动排除或报 artifact_id 冲突。

---

### P0-S3：如果继续使用现有 OCR/sidecar，必须修复自包含元数据

即使 P0 采用 QR，也建议修复现有 sidecar 模式，否则当前文档声称的 manifest-less 能力会与实际可靠配置冲突。

#### 目标

如下命令必须在不传 manifest 的情况下成功：

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

#### 修改点 1：`@CFG` 增加 payload profile

当前：

```text
@CFG|AT1|CC=32|LP=12|RC=2|IL=1|PG=4|CS=50|RS=42
```

建议 v2 兼容扩展：

```text
@CFG|AT1|CC=32|LP=12|RC=2|IL=1|PG=4|CS=50|RS=42|PF=O1|PM=modular-sum
```

映射建议：

```text
PF=S1 -> safe-base32-v1
PF=O1 -> ocr-safe-human-correctable-v1
PM=xor
PM=modular-sum
```

不要直接写超长 profile 名，避免 OCR 误识别。

#### 修改点 2：更新 parser

文件：`enc2sop/transport/protocol.py`

更新：

```text
parse_cfg_line()
```

让它接受可选字段：

```text
PF
PM
```

并保证旧格式仍然兼容。

#### 修改点 3：更新 embedded manifest 推断

文件：`enc2sop/transport/ocr_embedded.py`

更新：

```text
build_inferred_manifest_from_metadata()
```

必须：

1. 读取 `PF`。
2. 设置 `manifest["payload_alphabet_profile"]`。
3. 使用 `encoded_length_for_profile(compressed_size, profile)` 计算长度，而不是固定 `safe_base32_encoded_length()`。
4. 读取 `PM` 或根据 profile 推断 parity symbol mode。
5. 传给 `_decode_manifest_guided_sidecar_payload(... payload_alphabet_profile=profile)`。

#### 修改点 4：更新 embedded OCR whitelist

文件：`enc2sop/transport/ocr_embedded.py`

当前 `meta_whitelist` 不一定覆盖新字段。要加入：

```text
PFMOSXabcdefghijklmnopqrstuvwxyz- 等必要字符
```

更推荐只用短码 `PF=O1/S1`，减少 whitelist 复杂度。

#### 修改点 5：修正字段语义

`@META` 当前类似：

```text
@META|AT1|ID=...|PAGE=1/1|CHUNKS=8|TOTAL=3
```

这里 `CHUNKS=8` 是本页 data lines，不是 total chunks；`TOTAL=3` 是 data chunks。语义容易误导。

建议新增 v2 字段，不破坏旧字段：

```text
@META|AT1|ID=...|PAGE=1/1|LINES=8|DATA=3
```

旧 parser 继续支持 `CHUNKS/TOTAL`。

#### 验收测试

新增测试：

```text
tests/test_qrcode_helper_sidecar.py::test_manifestless_ocr_safe_sidecar_with_parity_roundtrip
```

测试内容：

1. export 使用 `ocr-safe-human-correctable-v1`。
2. `redundancy_copies=2`。
3. `parity_group_size=4`。
4. recover-images 不传 manifest。
5. 输出文件 SHA256 等于原文件。

---

### P0-S4：真实手机照片预处理进入简单主链路

如果采用 QR 模式，这一步大部分由 QR detector 解决。若继续 sidecar/OCR 模式，则必须把图像预处理产品化。

#### 最小实现

新增命令参数：

```bash
python soenc.py cm scan --image-input photos --out-string recovered.sox1 --preprocess auto
```

或：

```bash
python qrcode_helper.py recover-images ... --preprocess-photo auto
```

处理流程：

```text
读取图片
  -> EXIF 自动旋转
  -> 灰度化
  -> 页面轮廓检测
  -> 四点透视矫正
  -> 去阴影/自适应阈值
  -> 多尺度 decode
  -> 失败记录 retake reason
```

#### 输出质量报告

每次 scan/recover-images 都应写：

```text
scan_report.json
```

字段：

```json
{
  "image_count": 10,
  "decoded_chunks": 9,
  "missing_chunks": [4],
  "bad_images": [
    {
      "path": "IMG_004.jpg",
      "reason": "qr_not_found_or_crc_failed",
      "suggestion": "retake page 5 closer, avoid glare"
    }
  ]
}
```

---

### P0-S5：端到端命令封装

最终用户不应该理解 export/recover/certify/capture-corpus。

新增一组高层命令：

```bash
# 1. 密闭环境：加密并渲染
python soenc.py cm send \
  --input ./secret.bin \
  --key-file ./key.bin \
  --output-dir ./send_pages \
  --mode qr

# 2. 外界环境：扫描并解密
python soenc.py cm receive \
  --image-input ./phone_photos \
  --key-file ./key.bin \
  --output ./restored.bin \
  --work-dir ./receive_work
```

`send` 内部等价于：

```text
encrypt -> render
```

`receive` 内部等价于：

```text
scan -> decrypt
```

#### send 输出

```text
send_pages/
  manifest.json               # 仅供辅助，不是恢复必需
  payload.sox1                # 可选调试输出；生产可选择不落盘
  pages/page_0001.png
  pages/page_0002.png
  instructions.md
```

#### receive 输出

```text
receive_work/
  scan_report.json
  recovered.sox1
  decrypt_report.json
restored.bin
```

---

## 6. P1 施工任务

P0 只需要解决“能用、闭环、清晰失败”。P1 再做增强。

### P1-S1：公钥加密模式

新增：

```bash
python soenc.py cm keygen --public public.pem --private private.pem
python soenc.py cm encrypt --input secret.bin --recipient-public-key public.pem --out-string secret.sox1
python soenc.py cm decrypt --input-string secret.sox1 --private-key private.pem --output restored.bin
```

建议用混合加密：

```text
X25519/RSA-OAEP 包装 data key + AES-256-GCM 加密数据
```

P0 不强制做，避免拖慢。

### P1-S2：大文件分卷

当前 transport 默认 compressed limit 是 64 KiB。对“任何数据”来说，这只是小文件能力。

P1 做：

```text
large file -> volume_0001.sox1, volume_0002.sox1, ...
```

每卷独立加密或共享 envelope group metadata，最后重组校验整体 SHA256。

### P1-S3：一页多 QR 与重复布局

优化打印/拍摄效率：

```text
每页 4/6/8 个 QR
每个 chunk 至少出现 2 次
页脚显示 retake 编号
```

### P1-S4：保留现有 certification，但降级为实验/证据工具

现有 `certify / archive-evidence / capture-corpus` 可以保留，但不要放在普通主流程里。

普通主流程：

```text
send / receive
```

证据链流程：

```text
certify / archive / status
```

二者不要混在一起。

---

## 7. 后续 GPT5.5 的施工顺序

请严格按以下顺序做，不要扩围。

### 第 1 步：入口解耦

目标：`python soenc.py transport --help` 与 `python soenc.py cm --help` 可启动。

允许改动：

```text
enc2sop/cli.py
enc2sop/crossmedia/* 新增
soenc.py 如有必要可轻微改
requirements-crossmedia.txt 新增
```

禁止改动：

```text
promotion_*
release_*
docs/PLATFORM_LAUNCH_*
GitHub evidence 相关逻辑
```

### 第 2 步：实现 SOX1 加密信封

目标：文件 bytes 与 SOX1 字符串双向转换。

新增测试：

```text
tests/test_crossmedia_crypto_envelope.py
```

最小测试：

```text
test_encrypt_decrypt_roundtrip_key_file
test_decrypt_fails_with_wrong_key
test_decrypt_fails_after_tamper
test_envelope_does_not_embed_key_material
test_binary_file_roundtrip
```

### 第 3 步：实现 QR render/scan

目标：SOX1 字符串与 QR 图片双向转换。

新增测试：

```text
tests/test_crossmedia_qr_transport.py
```

最小测试：

```text
test_render_scan_roundtrip_png
test_scan_accepts_duplicate_images
test_scan_reports_missing_chunks
test_scan_rejects_crc_tamper
test_scan_rejects_mixed_artifact_ids
test_scan_jpeg_roundtrip
test_scan_rotated_image_roundtrip
```

### 第 4 步：实现 send/receive

目标：一个命令生成页面，一个命令从照片恢复文件。

新增测试：

```text
tests/test_crossmedia_e2e.py
```

最小测试：

```text
test_send_receive_roundtrip_small_text
test_send_receive_roundtrip_binary
test_receive_wrong_key_fails
test_receive_missing_page_outputs_retake_plan
```

### 第 5 步：修复现有 OCR/sidecar manifest-less bug

目标：不要让已有 `qrcode_helper.py` 在 OCR-safe + parity + 无 manifest 场景下继续错解。

新增测试：

```text
test_manifestless_ocr_safe_sidecar_with_parity_roundtrip
```

这一步可以在 QR 主链路之后做，但必须做，否则旧文档与实际行为会冲突。

---

## 8. 关键验收脚本

后续实现完成后，至少提供一个可复制的 smoke 脚本。

建议新增：

```text
scripts/crossmedia_smoke.sh
scripts/crossmedia_smoke.ps1
```

脚本内容：

```bash
set -euo pipefail
WORK=.tmp_crossmedia_smoke
rm -rf "$WORK"
mkdir -p "$WORK"

python soenc.py cm keygen --key-file "$WORK/key.bin"
printf 'hello cross media encrypted transport' > "$WORK/plain.txt"

python soenc.py cm send \
  --input "$WORK/plain.txt" \
  --key-file "$WORK/key.bin" \
  --output-dir "$WORK/send" \
  --mode qr

# 模拟手机照片：把 PNG 转 JPEG，做轻微旋转/缩放
python scripts/simulate_capture_distortions.py \
  --input "$WORK/send/pages" \
  --output "$WORK/photos" \
  --jpeg-quality 85 \
  --rotate-deg 1.0

python soenc.py cm receive \
  --image-input "$WORK/photos" \
  --key-file "$WORK/key.bin" \
  --output "$WORK/restored.txt" \
  --work-dir "$WORK/receive"

cmp "$WORK/plain.txt" "$WORK/restored.txt"
echo CROSSMEDIA_SMOKE_OK
```

---

## 9. 当前代码中可以复用的实现点

不要重写一切，以下可直接复用：

1. `protocol.crc16_hex()`：分片 CRC。
2. `protocol.utc_now_iso()`：时间戳。
3. `protocol.sha256_hex()`：整体 hash。
4. `qrcode_helper.AirgapTransportLayer.export_artifact()` 的压缩/分片/redundancy 思路。
5. `parser` 里的 missing chunk / duplicate conflict 思路。
6. `recover` 里的 analyze report / retake plan 思路。
7. `scripts/real_capture_text_transport.py` 的 “prepare/certify” 概念，但要改成更简单的 `send/receive`。

不要复用为 P0 主路径：

1. promotion/release evidence。
2. GitHub CI proof。
3. capture corpus 全证据链。
4. local-embedded key 作为真实加密方案。

---

## 10. 最终结论

当前项目不是完全卡死，核心编码/渲染/恢复能力已经存在；但它被三个问题拖住了：

1. **产品主链路不清晰**：普通用户需要的是 `send/receive`，不是 `certify/archive/status`。
2. **加密层和传输层耦合不正确**：现有加密偏 Python 代码保护，缺少通用数据信封；local-embedded 不适合真实保密传输。
3. **手机照片鲁棒性没有产品化**：生成图可恢复，但真实拍照的旋转、透视、裁剪需要 QR 或自动纠偏进入主流程。

后续 GPT5.5 应先实现：

```text
P0-S0 入口解耦
P0-S1 SOX1 通用加密信封
P0-S2 QR 分片视觉传输
P0-S5 send/receive 高层命令
P0-S3 修复旧 sidecar manifest-less 元数据 bug
```

做到这一步，项目才真正对齐用户最初目标：

```text
任意数据 -> 加密字符串 -> 图片 -> 手机拍摄 -> 字符串 -> 解密 -> 原始数据
```
