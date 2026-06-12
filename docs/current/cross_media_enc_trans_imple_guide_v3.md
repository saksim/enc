# 跨介质加密解密传送与代码保护链路：V0.3 唯一施工蓝图与 GPT5.5 落地指南

> 更新时间：2026-06-09  
> 基础文档：`cross_media_encrypted_transport_implementation_guide_v2.md`  
> 本轮新增：正式纳入 `decryption_helper.py / encryption_helper.py / py2_linux_rec_opera.py` 三文件代码保护链路  
> 当前唯一目标：围绕真实可落地的“跨介质加密解密传送”完成主链路，同时保留并隔离“原始 PY -> 加密 PY -> SO/PYD”的代码保护链路，避免后续 GPT5.5 施工时把 OCR、SOX1、Cython 加固、反汇编防护混成一个不可控的大工程。

---

## 0. V0.3 总结论

V0.3 相比 V0.2 的最大变化，是把项目正式拆成两条主线：

```text
P0-A：跨介质数据传输链路
  任意数据 bytes
    -> SOX1 加密字符串
    -> QR 图片
    -> 手机拍摄
    -> 恢复 SOX1 字符串
    -> 解密回原始 bytes

P0-B：代码保护 / Native Packaging 链路
  原始 .py
    -> encryption_helper.py 加密源码片段
    -> protected staging .py
    -> py2_linux_rec_opera.py 编译
    -> .so / .pyd 可运行扩展
    -> decryption_helper.py 运行时解密执行
```

两条链路都重要，但它们解决的问题不同：

```text
跨介质数据传输链路：解决“数据如何通过图片从密闭环境传出去，并在外界可靠恢复”。
代码保护链路：解决“Python 源码如何被保护后形成可运行 SO/PYD，避免直接暴露源码”。
```

必须固定以下边界：

```text
SOX1 负责数据保密；
QR / OCR / sidecar 负责跨介质传送；
encryption_helper / decryption_helper / py2_linux_rec_opera 负责代码保护；
Cython / SO / PYD / 混淆只能提高逆向成本，不能替代密钥安全；
local-embedded 只能作为 dev/demo/anti-casual 模式，不能作为强安全模式。
```

---

## 1. 项目唯一目标与非目标

### 1.1 唯一业务目标

本项目的第一目标不是做一个完整发布平台，不是做证据归档系统，不是做大型 OCR 平台，也不是承诺绝对防反汇编。

第一目标只有一个：

```text
任何数据在密闭环境中，先通过代码加密成字符串；
再把字符串转化为一张张图片；
通过手机拍摄或截图带到外界；
外界使用同一套代码，从图片恢复字符串并解密出原始数据。
```

### 1.2 必须兼容的第二目标

当前代码包中已经存在一条有价值的代码保护链路：

```text
原始 PY -> 加密 PY -> SO/PYD 可运行文件
```

这条链路不能被 OCR/QR 主链路覆盖掉，也不应该被误删。它必须被纳入正式蓝图，作为独立的 Code Protection Layer。

### 1.3 明确非目标

V0.3 阶段明确不做或不扩大的内容：

```text
不扩展 release / archive / promotion / evidence 平台化治理；
不优先做多模型 OCR 大平台；
不承诺 local-embedded 模式可防强逆向；
不承诺 SO/PYD 后源码绝对不可恢复；
不让 cm/transport 命令依赖 Cython、Crypto、代码保护构建链路才能启动；
不把 OCR 结果直接送入 decrypt；
不把 key/passphrase/private key 写进图片、manifest、SOX1、scan_report 或二进制。
```

---

## 2. 当前项目能力重新分层

### 2.1 已有跨介质传输相关能力

当前代码中已有以下可复用能力：

```text
qrcode_helper.py                         # 旧的空气隔离/图片传输主入口
enc2sop/transport/protocol.py            # 编码、CRC、OCR normalization、payload profile
enc2sop/transport/render.py              # 文本页 + binary sidecar 渲染
enc2sop/transport/ocr_runtime.py         # sidecar / tesseract / easyocr / external OCR 编排
enc2sop/transport/ocr_embedded.py        # 无 manifest 时从图片 OCR 读取 embedded metadata
enc2sop/transport/parser.py              # OCR 文本解析、纠错、parity 恢复
enc2sop/transport/recover.py             # verify / analyze / recover 实现
scripts/real_capture_text_transport.py   # 文本加密 -> 图片 -> 真实捕获 -> 解密试验脚本
```

这些能力证明当前项目不是从零开始。旧链路已经能完成基础图片恢复，但尚未形成面向真实手机拍摄的稳定 P0 产品入口。

### 2.2 已有代码保护相关能力

本轮重点确认的三文件组合如下：

```text
encryption_helper.py
  负责扫描原始 Python 文件，选择函数/类/模块片段，使用 AES-GCM 等方式加密源码片段，生成 protected staging .py，并写入 build_manifest 等构建信息。

decryption_helper.py
  负责运行时从 key_ref 获取 key，解密 payload，将源码 compile/exec 注入当前命名空间，使 protected staging 或编译后的 artifact 能继续运行。

py2_linux_rec_opera.py
  负责批量将 protected staging tree 中的 .py / .pyx 编译为 Linux .so 或 Windows .pyd，并处理复制依赖、清理中间 .c、输出 dist 等发布动作。
```

三者组成的是：

```text
原始 .py
  -> 加密源码片段
  -> protected staging .py
  -> Cython 编译
  -> .so / .pyd
  -> 外界可 import / 可运行
```

这条链路属于：

```text
Code Protection / Native Packaging Layer
```

不属于 OCR 层，不属于 QR 层，也不属于 SOX1 数据信封层。

---

## 3. 两条链路的职责边界

### 3.1 P0-A：跨介质数据传输链路

目标：

```text
密闭环境内任意 bytes
  -> 加密字符串
  -> 图片
  -> 手机拍摄
  -> 外界恢复字符串
  -> 解密回 bytes
```

保护对象：

```text
任意数据内容，包括文件、文本、压缩包、SO/PYD 包、模型文件、小型配置包等。
```

核心模块建议：

```text
enc2sop/crossmedia/crypto_envelope.py
enc2sop/crossmedia/qr_transport.py
enc2sop/crossmedia/scan_report.py
enc2sop/crossmedia/cli.py
```

核心命令：

```bash
python soenc.py cm send \
  --input ./secret.bin \
  --key-file ./key.bin \
  --output-dir ./send_pages \
  --mode qr

python soenc.py cm receive \
  --image-input ./phone_photos \
  --key-file ./key.bin \
  --output ./restored.bin \
  --work-dir ./receive_work
```

### 3.2 P0-B：代码保护 / SO-PYD 链路

目标：

```text
原始 Python 源码
  -> protected staging
  -> SO/PYD native artifact
  -> 外界可运行，但不直接暴露原始源码。
```

保护对象：

```text
Python 源码、算法实现、业务逻辑、模块结构。
```

核心模块：

```text
encryption_helper.py
decryption_helper.py
py2_linux_rec_opera.py
```

建议命令形态：

```bash
python soenc.py protect build \
  --src ./src_py \
  --out ./protected_staging \
  --key-mode local-embedded \
  --dev-insecure-ok

python soenc.py protect compile \
  --src ./protected_staging \
  --out ./dist_native \
  --target linux-so
```

或后续收敛为：

```bash
python soenc.py protect package \
  --src ./src_py \
  --out ./dist_native \
  --target linux-so \
  --key-mode license-file
```

### 3.3 两条链路如何组合

如果用户只想传输数据：

```text
secret.bin -> SOX1 -> QR pages -> phone -> restored.bin
```

如果用户想把 Python 代码安全带出去并能运行：

```text
密闭环境内：
  原始 .py
    -> protect build
    -> compile to .so/.pyd
    -> dist_native.zip

跨介质传输：
  dist_native.zip
    -> SOX1
    -> QR pages
    -> phone photos
    -> restored dist_native.zip

外界环境：
  unzip dist_native.zip
    -> import .so/.pyd
    -> run
```

这比“把原始 PY 带出去再编译”更符合代码保护目标。

---

## 4. 安全边界：必须诚实定义能防什么、不能防什么

### 4.1 跨介质数据链路的安全边界

SOX1 数据链路的安全前提是：

```text
图片、SOX1、manifest、scan_report、代码都可以被攻击者拿到；
攻击者没有 key-file / passphrase / private key；
在此前提下，攻击者不能解密原始数据。
```

因此，SOX1 信封中允许包含：

```text
schema/version
cipher suite
nonce
salt
kdf 参数
ciphertext
tag
原始文件大小
原始文件 hash
chunk/page 元数据
```

严禁包含：

```text
AES key
key shard
passphrase
private key
可还原 key 的任何材料
```

### 4.2 代码保护链路的安全边界

`encryption_helper.py + decryption_helper.py + py2_linux_rec_opera.py` 能做到：

```text
防止普通用户直接看到 .py 源码；
防止简单复制、简单篡改、简单替换 runtime；
提高逆向成本；
让源码保护从“明文可见”提升到“需要逆向能力”。
```

不能承诺：

```text
攻击者拿到完整 artifact 后绝对无法还原逻辑；
攻击者控制运行环境后绝对无法 dump 明文；
local-embedded 模式下仍然强保密；
Cython 编译成 .so/.pyd 后就不可逆；
代码混淆可以替代密钥安全。
```

### 4.3 local-embedded 的正式定位

`local-embedded` 必须降级为：

```text
dev / demo / anti-casual 模式
```

不能作为：

```text
production secure 模式
强保密模式
防强反汇编模式
```

因为在 local-embedded 模式下，通常存在：

```text
加密 payload 在 artifact 中；
key_ref 或 key shards 也在 artifact 中；
runtime 解密逻辑在 artifact 中；
攻击者可以 hook decrypt/exec/compile 或 dump 内存。
```

P0-B 施工时必须加入明确提示：

```text
local-embedded is insecure for strong reverse-engineering scenarios.
Use only for dev/demo/anti-casual protection.
```

### 4.4 license-file 的正式定位

`license-file` 只能算“密钥外置”，不能天然算“密钥安全”。

它只有在以下条件成立时才有实际安全价值：

```text
license 文件不随 artifact 一起传出；
license 文件由用户单独持有；
license 文件绑定设备/环境；
license 文件受签名、服务端或 KMS 控制；
license 文件泄露后可以吊销。
```

如果 license 文件和 SO/PYD 一起交付，本质上仍然是：

```text
密文 + key 同时交给外界
```

只能提高组织性，不能提供强安全。

### 4.5 remote-kms 的正式定位

`remote-kms` 方向正确，但如果当前只是 stub，就不能被文档写成已具备能力。

它应被列为：

```text
P1/P2 安全增强方向
```

只有完成以下能力后，才可作为正式安全模式：

```text
runtime 能向 KMS 获取解密授权；
KMS 能做身份验证、设备绑定、频率限制、吊销；
KMS 不直接把长期主密钥暴露给客户端；
日志能记录授权、失败、异常调用；
runtime 失败时能输出明确错误，不 fallback 到 insecure local mode。
```

---

## 5. OCR/QR 策略：不要把 OCR 当成零错误通道

### 5.1 为什么 OCR 总出问题

本项目中的 OCR 失败，不一定是 OCR 模型太差，而是场景天然敏感：

```text
普通 OCR：识别文章，错一两个字，人仍然能理解。
本项目 OCR：识别加密字符串，错一个字符，AES-GCM tag / SHA 校验就会整体失败。
```

因此 OCR 在本项目中不能作为最终答案来源，只能作为候选来源。

### 5.2 P0 必须采用 QR-first

P0 主链路必须是：

```text
SOX1 string
  -> QR chunk pages
  -> phone photos
  -> QR detect/decode
  -> chunk verify
  -> assemble SOX1
  -> decrypt
```

原因：

```text
QR 天生为相机识别设计；
QR 具备结构化定位、纠错、分片承载能力；
QR 解码结果比纯文本 OCR 更适合加密字符串传输；
失败时更容易定位缺页、坏页、重复页。
```

### 5.3 OCR 的正确位置

OCR 不废弃，但必须降级为：

```text
P1 fallback
P1 人工可读备份
P2 多模型候选输入
P2 视觉大模型辅助纠偏/定位/转写
```

所有 OCR provider 必须统一接入：

```text
OCRProvider
  -> TextObservation
  -> Normalizer
  -> Verifier
  -> Assembler
  -> scan_report / retake_plan
```

禁止：

```text
每个 OCR 模型各写一套 parser；
OCR 输出直接进入 decrypt；
LLM 根据语义猜测密文；
模型置信度替代 CRC/SHA/AEAD tag；
失败时只报 hash mismatch。
```

---

## 6. 总体架构：五层模型

V0.3 起，项目正式按五层建模：

```text
A. Crypto Envelope Layer
   bytes <-> SOX1 encrypted string
   负责 AES-GCM / KDF / key-file / passphrase / public/private key

B. Visual Transport Layer
   SOX1 string <-> QR/images/photos <-> SOX1 string
   负责 QR / OCR / sidecar / chunk / page / scan

C. Verification Layer
   CRC / SHA / AEAD tag / scan_report / retake_plan
   负责证明恢复结果可信，并指导重拍

D. Code Protection Layer
   .py <-> encrypted staging .py <-> .so/.pyd
   负责源码保护和 native packaging

E. Runtime/Release Hardening Layer
   manifest / native runtime loader / signing / fingerprint / anti-tamper
   负责提高篡改与逆向成本
```

层间边界：

```text
Crypto Envelope 不关心图片；
Visual Transport 不关心明文和 key；
Verification 不相信单一 OCR 模型；
Code Protection 不承诺保存秘密；
Runtime Hardening 不替代密码学安全。
```

---

## 7. P0-A 施工方案：跨介质数据传输链路

### P0-A0：CLI 解耦

目标：

```text
python soenc.py cm --help
python soenc.py cm send --help
python soenc.py cm receive --help
```

即使未安装代码保护、Cython、release、remote-kms 相关依赖，也必须能启动。

施工要求：

```text
enc2sop/cli.py 顶层只保留轻量依赖；
protect/build/release 相关模块全部 lazy import；
cm/transport 不 import encryption_helper.py；
cm/transport 不 import py2_linux_rec_opera.py；
cm/transport 不要求 Cython；
cm/transport 不因为 Crypto 缺失在 help 阶段崩溃。
```

验收：

```bash
python soenc.py cm --help
python soenc.py cm send --help
python soenc.py cm receive --help
```

### P0-A1：SOX1 加密信封

新增或收敛模块：

```text
enc2sop/crossmedia/crypto_envelope.py
```

最小 API：

```python
encrypt_bytes(data: bytes, key_provider: KeyProvider) -> str
decrypt_to_bytes(sox1: str, key_provider: KeyProvider) -> bytes
```

KeyProvider：

```text
KeyFileProvider
PassphraseProvider
FutureRecipientPublicKeyProvider
```

P0 支持：

```text
--key-file
--passphrase
```

P0 禁止：

```text
--local-embedded
--hardcoded-key
--embed-key
```

SOX1 建议格式：

```text
SOX1.<base64url(json_header)>.<base64url(ciphertext)>.<base64url(tag)>
```

header 必含：

```text
schema = SOX1
version
cipher = AES-GCM 或 ChaCha20-Poly1305
kdf = none / PBKDF2 / scrypt / Argon2id
salt
nonce
original_size
original_sha256
created_at 可选
```

验收：

```text
encrypt -> decrypt 后 bytes 完全一致；
篡改任意字符必须失败；
错误 key 必须失败；
SOX1/header 不包含 key/passphrase/private key/key shard。
```

### P0-A2：QR-first render/scan

新增或收敛模块：

```text
enc2sop/crossmedia/qr_transport.py
```

数据流：

```text
SOX1 string
  -> chunk
  -> page header
  -> QR payload
  -> pages/*.png
```

每个 QR payload 必含：

```text
protocol = SOQ1
transfer_id
page_index
page_count
chunk_index
chunk_count
chunk_payload
chunk_crc32
payload_profile
optional_total_sha256
```

验收：

```text
render 后不依赖 manifest 也能恢复；
照片乱序输入可以恢复；
重复照片不会破坏恢复；
缺页时输出缺页列表；
坏页时输出坏页列表；
轻微旋转/缩放/JPEG 压缩可恢复。
```

### P0-A3：send / receive 主命令

P0 只向普通用户暴露两个主命令：

```bash
python soenc.py cm send \
  --input ./secret.bin \
  --key-file ./key.bin \
  --output-dir ./send_pages \
  --mode qr

python soenc.py cm receive \
  --image-input ./phone_photos \
  --key-file ./key.bin \
  --output ./restored.bin \
  --work-dir ./receive_work
```

调试命令可以保留，但不得成为普通用户必需路径：

```bash
python soenc.py cm encrypt
python soenc.py cm render
python soenc.py cm scan
python soenc.py cm decrypt
python soenc.py cm verify
```

### P0-A4：scan_report / retake_plan

失败不能只报：

```text
hash mismatch
```

必须输出：

```text
receive_work/scan_report.json
receive_work/retake_plan.txt
```

`scan_report.json` 最小字段：

```json
{
  "transfer_id": "...",
  "status": "success|need_retake|failed",
  "expected_pages": 10,
  "seen_pages": [0, 1, 3],
  "missing_pages": [2],
  "bad_pages": [5],
  "duplicate_pages": [1],
  "decoded_chunks": 9,
  "failed_chunks": 1,
  "image_diagnostics": [],
  "next_action": "retake page 2 and page 5"
}
```

`retake_plan.txt` 必须用人话说明：

```text
缺第几页；
哪张照片坏；
建议更近一点、更正一点、更亮一点、避免反光、保持 QR 边框完整。
```

### P0-A5：no-secret-leakage tests

测试目标：

```text
send_pages/*.png
manifest.json
scan_report.json
SOX1 string
log
```

均不得包含：

```text
key bytes
passphrase
private key
key shard
license secret
```

验收建议：

```bash
pytest tests/test_crossmedia_no_secret_leakage.py
```

### P0-A6：crossmedia smoke

新增：

```text
scripts/smoke_crossmedia_qr.py
```

覆盖：

```text
生成临时随机文件；
生成 key-file；
cm send 输出 QR pages；
复制/压缩/轻微扰动图片；
cm receive 恢复文件；
SHA256 一致；
错误 key 失败；
缺页输出 retake plan。
```

---

## 8. P0-B 施工方案：代码保护 / SO-PYD 链路

### P0-B0：正式登记三文件职责

必须在文档和代码注释中明确：

```text
encryption_helper.py：源码加密与 protected staging 生成；
decryption_helper.py：运行时解密、compile、exec；
py2_linux_rec_opera.py：将 protected staging 编译为 .so/.pyd。
```

并明确：

```text
这三者不属于 OCR/QR 传输层；
这三者不负责跨介质恢复图片；
这三者不能替代 SOX1 数据加密；
这三者不能保证强反汇编场景下绝对安全。
```

### P0-B1：protect/build 与 cm/transport 解耦

当前最重要的工程要求：

```text
cm/transport 可独立启动；
protect/build/release 需要的依赖不能污染 cm/transport；
Cython、Crypto、native build 工具缺失时，不能影响 cm send/receive --help。
```

施工动作：

```text
将 encryption_helper.py 的 import 移到 protect 命令内部；
将 py2_linux_rec_opera.py 的 import 移到 compile/build 命令内部；
将 decryption_helper.py 的 runtime 依赖与 cm receive 解耦；
CLI 顶层只注册命令，不执行 heavy import。
```

验收：

```bash
python soenc.py cm --help
python soenc.py protect --help
```

其中 `cm --help` 不允许因为 protect 依赖缺失失败。

### P0-B2：code-protection smoke

新增或保留 smoke：

```text
scripts/smoke_code_protection.py
```

覆盖：

```text
创建临时 demo_module.py；
其中包含函数 add(a,b) 和类 Demo；
调用 encryption_helper.py 生成 protected staging；
调用 py2_linux_rec_opera.py 编译成 .so/.pyd；
在干净目录 import 编译产物；
调用函数和类方法；
输出与原始 .py 一致。
```

验收：

```text
原始 PY -> protected staging -> SO/PYD -> import -> function output 一致。
```

### P0-B3：release dist 安全清理

生成 dist 时必须确保不包含：

```text
原始 .py 明文源码；
protected staging .py；
Cython 生成的 .c；
临时 build 目录；
未加密 payload dump；
debug key；
local key 明文；
未签名 manifest 中的敏感字段。
```

可包含：

```text
.so / .pyd
必要 runtime native extension
必要 package metadata
非敏感 manifest
README / usage
```

验收：

```bash
python scripts/check_dist_no_source_leak.py ./dist_native
```

检查：

```text
find dist_native -name '*.py' 只允许 __init__.py 或明确白名单；
find dist_native -name '*.c' 必须为空；
grep/strings 不得出现原始源码中的关键函数体片段；
grep/strings 不得出现 key/passphrase/private key。
```

### P0-B4：local-embedded 显式 insecure 标记

所有 local-embedded 使用必须满足：

```text
CLI 显式要求 --dev-insecure-ok；
manifest 标记 key_mode = local-embedded-dev-insecure；
日志输出 warning；
文档写明不能防强逆向。
```

示例：

```bash
python soenc.py protect package \
  --src ./src_py \
  --out ./dist_native \
  --key-mode local-embedded \
  --dev-insecure-ok
```

如果没有 `--dev-insecure-ok`，P0-B 应直接失败。

### P0-B5：license-file 外置化规范

如果使用 license-file：

```text
dist_native 中默认不得包含 license 文件；
license 文件路径应由用户运行时提供；
license 文件可选绑定机器指纹；
license 文件应可签名、可吊销；
如果用户显式选择 bundle-license，必须输出 insecure warning。
```

### P0-B6：runtime integrity smoke

如果已有 runtime native loader / fingerprint / manifest 签名：

```text
必须保留，但归类为 hardening；
不能把它写成 strong secrecy；
验收必须覆盖 runtime 被替换、manifest 被篡改、digest 不一致时失败。
```

---

## 9. P1 施工方案：增强能力但不扩散主线

### P1-A：OCR fallback 与多模型候选

目标：

```text
在 QR-first 可用后，再支持 OCR 文本页 fallback。
```

统一接口：

```python
class OCRProvider:
    def recognize(self, image_path: str) -> list[TextObservation]: ...
```

禁止每个 provider 自己解析最终 payload。

provider 只输出候选：

```text
text
confidence
bbox
provider_name
image_id
```

最终由统一 verifier 判断：

```text
format check
line crc
chunk crc
page crc
total sha256
AEAD tag
```

### P1-B：manifest-less sidecar 元数据补齐

必须修复旧链路中：

```text
ocr-safe-human-correctable-v1 + redundancy/parity + 无 manifest
```

可能因 PF/PM 元数据缺失导致 hash mismatch 的问题。

embedded metadata 必须包含：

```text
payload alphabet profile
parity symbol mode
chunk count
page count
codec version
crc/hash
```

### P1-C：public/private key 模式

更安全的跨介质方案：

```text
外界生成 public.pem / private.pem；
密闭环境只拿 public.pem；
密闭环境用 public.pem 加密并生成 QR 图片；
外界用 private.pem 解密。
```

优点：

```text
密闭环境输出物中不包含解密私钥；
图片、SOX1、manifest 泄露也无法直接解密；
适合一次性传输敏感数据。
```

建议实现：

```text
X25519 / HPKE / RSA-OAEP + AES-GCM envelope
```

### P1-D：license-file 设备绑定

目标：

```text
让 license-file 不只是旁边的 key 文件，而具备环境绑定、签名、过期、吊销能力。
```

字段建议：

```text
license_id
subject
allowed_module_hashes
machine_fingerprint_hash
expires_at
key_envelope
signature
```

### P1-E：release artifact tamper report

对于 SO/PYD 发布包，加入：

```text
manifest signature
binary digest
runtime digest
import-time check
failure report
```

但仍然标注为：

```text
anti-tamper / integrity hardening
```

不是强保密边界。

---

## 10. P2 施工方案：强安全与工程增强

### P2-A：remote KMS 真实现

将当前 stub 变成真实能力：

```text
runtime 请求 KMS；
KMS 做身份认证；
KMS 返回短期授权或 envelope unwrap；
KMS 记录审计日志；
KMS 支持吊销和限频；
runtime 不 fallback 到 insecure local mode。
```

### P2-B：视觉大模型辅助

视觉大模型只能做：

```text
定位 QR 区域；
判断照片是否模糊/反光/裁剪；
辅助 OCR 候选生成；
生成重拍建议。
```

禁止做：

```text
猜测密文；
补全未通过 CRC 的 payload；
绕过 verifier；
用自然语言理解替代密码学校验。
```

### P2-C：代码混淆 / strip symbols / anti-debug

可作为 hardening：

```text
strip symbols
Cython/Nuitka 编译选项优化
字符串混淆
反调试检测
完整性自检
RASP-like hooks
```

但必须持续写明：

```text
这些只能提高逆向成本，不能保存秘密。
```

---

## 11. 后续 GPT5.5 施工总顺序

后续 GPT5.5 不要自由发挥，严格按以下顺序施工。

### 第一阶段：P0-A0 入口解耦

目标：

```text
cm/transport 独立可启动，不被 protect/build 依赖拖死。
```

提示词：

```text
请只施工 P0-A0：CLI 入口解耦。
要求 python soenc.py cm --help / send --help / receive --help 在未安装 Cython、Crypto、native build 相关依赖时也能启动。
禁止修改 OCR 解析逻辑、禁止修改 encryption_helper 的核心加密逻辑、禁止扩展 release/promotion。
```

### 第二阶段：P0-A1 SOX1 envelope

目标：

```text
任意 bytes <-> SOX1 encrypted string。
```

提示词：

```text
请只施工 P0-A1：实现 enc2sop/crossmedia/crypto_envelope.py。
支持 key-file/passphrase，禁止 local-embedded/hardcoded-key。
新增单测覆盖正确解密、错误 key 失败、任意字符篡改失败、SOX1 不泄露 key。
```

### 第三阶段：P0-A2 QR-first render/scan

目标：

```text
SOX1 <-> QR pages <-> scanned photos <-> SOX1。
```

提示词：

```text
请只施工 P0-A2：实现 QR-first render/scan。
每个 QR payload 自带 transfer_id、page_index、page_count、chunk_crc，不依赖外部 manifest 恢复。
新增缺页、重复页、乱序页、坏页测试。
```

### 第四阶段：P0-A3 send/receive

目标：

```text
一个命令发送，一个命令恢复。
```

提示词：

```text
请只施工 P0-A3：实现 python soenc.py cm send / receive。
主链路为 input -> SOX1 -> QR pages -> photos -> SOX1 -> output。
调试命令可保留，但普通路径不得要求用户手动调用 encrypt/render/scan/decrypt。
```

### 第五阶段：P0-A4 scan_report/retake_plan

目标：

```text
失败可操作。
```

提示词：

```text
请只施工 P0-A4：为 receive 输出 scan_report.json 与 retake_plan.txt。
缺页、坏页、重复页、无法解码、hash mismatch、AEAD tag fail 都要有明确诊断。
禁止只输出 hash mismatch。
```

### 第六阶段：P0-B0/B1 代码保护链路登记与解耦

目标：

```text
decryption_helper.py、encryption_helper.py、py2_linux_rec_opera.py 作为 Code Protection Layer 正式纳入，但不污染 cm/transport。
```

提示词：

```text
请只施工 P0-B0/B1：将 decryption_helper.py、encryption_helper.py、py2_linux_rec_opera.py 正式登记为 Code Protection Layer，并完成 protect/build 与 cm/transport 的依赖解耦。
要求 cm --help 不 import encryption_helper 或 py2_linux_rec_opera。
不要改 QR/OCR 主链路。
```

### 第七阶段：P0-B2 code-protection smoke

目标：

```text
原始 PY -> protected staging -> SO/PYD -> import -> 输出一致。
```

提示词：

```text
请只施工 P0-B2：新增 code-protection smoke。
创建 demo_module.py，经过 encryption_helper.py 和 py2_linux_rec_opera.py 生成 SO/PYD，在干净目录 import 并验证函数/类输出一致。
不要改变 local-embedded 的算法实现，只添加 smoke 与必要的入口修复。
```

### 第八阶段：P0-B3/B4 dist 清理与 insecure 标记

目标：

```text
release dist 不泄露源码；local-embedded 明确标记为 insecure dev。
```

提示词：

```text
请只施工 P0-B3/B4：新增 dist no-source-leakage 检查，并将 local-embedded 标记为 dev/demo/anti-casual 模式。
使用 local-embedded 必须显式 --dev-insecure-ok。
不要实现 remote-kms，不要扩展发布治理。
```

---

## 12. 验收矩阵

| 编号 | 链路 | 验收项 | 必须结果 |
|---|---|---|---|
| A0-1 | CLI | `python soenc.py cm --help` | 无 Cython/Crypto 构建依赖也能启动 |
| A1-1 | SOX1 | bytes encrypt/decrypt | SHA256 一致 |
| A1-2 | SOX1 | 错误 key | 必须失败 |
| A1-3 | SOX1 | 篡改任意字符 | 必须失败 |
| A1-4 | SOX1 | secret leakage scan | 不包含 key/passphrase/private key |
| A2-1 | QR | render/scan | SOX1 完全恢复 |
| A2-2 | QR | 乱序/重复页 | 可恢复 |
| A2-3 | QR | 缺页 | 输出 missing pages |
| A2-4 | QR | 坏页 | 输出 bad pages |
| A3-1 | CM | send/receive smoke | restored 与 input SHA256 一致 |
| A4-1 | Report | receive 失败 | 输出 scan_report/retake_plan |
| B1-1 | 解耦 | cm 不 import protect heavy deps | help 不崩溃 |
| B2-1 | Code Protection | PY -> SO/PYD | import 成功，输出一致 |
| B3-1 | Dist | dist no source leakage | 无原始 .py、无 .c、无敏感 key |
| B4-1 | local-embedded | 无 `--dev-insecure-ok` | 必须失败 |
| B6-1 | Runtime Integrity | 替换 runtime/manifest | 必须失败或明确报警 |

---

## 13. 禁止事项清单

后续任何 GPT5.5 施工都必须遵守：

```text
禁止把 OCR 作为 P0 主路径；
禁止 OCR 输出直接 decrypt；
禁止 LLM 猜测密文；
禁止每个 OCR provider 各写一套 parser；
禁止 cm/transport import encryption_helper 或 py2_linux_rec_opera；
禁止 help 命令因为 Crypto/Cython 缺失失败；
禁止真实安全模式使用 local-embedded；
禁止把 key/passphrase/private key/key shard 写进图片、SOX1、manifest、scan_report、log、dist；
禁止把 Cython/SO/PYD 描述为绝对防反汇编；
禁止把 license-file 随 artifact 一起交付后仍宣称强安全；
禁止 release dist 包含原始源码、protected staging、生成的 .c；
禁止在 P0 阶段扩展 release/promotion/evidence 大平台。
```

---

## 14. 推荐目录结构

建议新增或收敛为：

```text
enc2sop/
  crossmedia/
    __init__.py
    crypto_envelope.py
    key_provider.py
    qr_transport.py
    scan_report.py
    cli.py

  transport/
    protocol.py
    render.py
    recover.py
    parser.py
    ocr_runtime.py
    ocr_embedded.py

  protect/
    __init__.py
    cli.py
    wrappers.py
    dist_check.py

scripts/
  smoke_crossmedia_qr.py
  smoke_code_protection.py
  check_dist_no_source_leak.py

tests/
  test_crossmedia_crypto_envelope.py
  test_crossmedia_qr_transport.py
  test_crossmedia_send_receive.py
  test_crossmedia_scan_report.py
  test_crossmedia_no_secret_leakage.py
  test_cli_lazy_import.py
  test_code_protection_smoke.py
  test_dist_no_source_leakage.py
```

如果短期不重构目录，也必须在文档和 CLI 中逻辑上完成分层。

---

## 15. 一句话最终蓝图

```text
P0-A 用 SOX1 + QR-first 解决“数据跨介质可靠传输与解密”；
P0-B 用 encryption_helper/decryption_helper/py2_linux_rec_opera 保留“原始 PY -> 加密 PY -> SO/PYD”的代码保护链路；
OCR 是未来候选增强，不是 P0 主路径；
Cython/SO/PYD 是逆向成本加固，不是密钥安全；
真正的保密边界永远是 key/passphrase/private key 不随输出物泄露。
```

---

## 16. 后续 GPT5.5 首轮施工推荐指令

建议下一轮不要直接说“把全部 V3 做完”，而是从最小切口开始：

```text
请基于 cross_media_encrypted_transport_implementation_guide_v3.md 施工 P0-A0。

目标：完成 CLI 入口解耦，让跨介质 cm/transport 主命令不被代码保护/build/release 依赖拖死。

范围：
1. soenc.py / enc2sop/cli.py 顶层轻量化；
2. protect/build/release/heavy crypto/Cython 依赖全部 lazy import；
3. python soenc.py cm --help、send --help、receive --help 可启动；
4. 不修改 OCR parser；
5. 不修改 encryption_helper/decryption_helper 的核心加密/解密逻辑；
6. 不扩展 release/promotion/evidence；
7. 新增最小 CLI lazy import 测试。

输出：
- 文件变更清单；
- 测试命令与结果；
- 是否触碰禁止扩围模块；
- 下一步只建议 P0-A1。
```

---

## 17. Current implementation completion handoff (2026-06-11)

The V0.3 implementation status for this blueprint is now tracked in:

```text
docs/current/cross_media_enc_trans_v3_gap_mapping.md
docs/current/cross_media_enc_trans_v3_completion_report.md
```

Current documented status:

```text
Remaining documented feature items: 0
Remaining documented hard blockers: 0
```

The final completed items are:

```text
P0-B2 strict native code-protection smoke
P1-A OCR candidate interface
P1-B manifestless OCR-safe sidecar verification
P2-B assistive-only visual model boundary
P1-E release artifact tamper report
```

This handoff does not change the blueprint boundaries:

```text
visual/OCR/model output remains assistive-only;
release_tamper_report.json is anti-tamper / integrity hardening only;
SOX1 crypto, key material, QR payload format, and promotion/evidence platform
expansion remain out of scope unless a later blueprint explicitly adds them.
```
