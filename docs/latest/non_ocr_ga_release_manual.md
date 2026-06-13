# Non-OCR GA Release Manual

发布日期：2026-06-13
状态：GA
适用范围：非 OCR 加密 / Python 代码保护 / native packaging / license-file 交付 / release governance

## 1. GA 结论

非 OCR 加密 / 代码保护能力已达到 GA 发布口径。

当前 GA 声明只覆盖以下主线：

```text
protect -> build -> package -> verify -> release
```

用户可以依赖：

```text
任意文件加密、解密、完整性校验
Python 代码保护后 native packaging 为 .pyd/.so，并保持 import/run 能力
license-file 外置交付
manifest signature
runtime integrity fail-closed
release approval / receipt / tamper report
promotion artifact bundle
non-OCR release gate
release 包 no-source-leak / reverse-cost check
```

本 GA 不覆盖：

```text
OCR / QR / cross-media 可靠传输
真实拍照、打印扫描、OCR-only 认证
remote-KMS 服务端正式上线
第三方逆向评估报告
```

## 2. 生产默认配置

生产和 GA release 默认使用 `license-file`，不得默认使用 `local-embedded`。

关键配置口径：

```text
keys.mode = license-file
bundle_license = false
require_manifest_signature = true
require_release_approval = true
runtime integrity checks = on
dist no-source-leak = required
release metadata = required
```

`local-embedded` 只允许用于开发、demo 或 anti-casual 场景，并且必须显式 opt-in。它不能被描述为可抵抗强攻击者的生产安全边界。

## 3. 标准发布证据

每次 GA release 必须归档以下证据：

```text
release_bundle.json
release_approval.json
release_receipt.json
release_tamper_report.json
promotion_evidence.json
promotion_audit_report.json
promotion_artifact_audit_report.json
promotion_run_receipt.json
promotion_artifact_bundle.zip
non_ocr_release_gate_report.json
rotation_rehearsal_report.json
```

验收条件：

```text
non_ocr_release_gate_report.passed == true
promotion_audit_report.passed == true
promotion_artifact_audit_report.passed == true
promotion_run_receipt.passed == true
rotation_rehearsal_report.status == passed
rotation_rehearsal_report.old_key_rejected == true
release_tamper_report.success == true
```

## 4. License-File 交付验证

生产交付必须覆盖以下运行时变量：

```text
SOENC_LICENSE_FILE
SOENC_LICENSE_VERIFY_KEY_B64
SOENC_MACHINE_FINGERPRINT
SOENC_LICENSE_REVOCATION_FILE
```

必须验证的 fail-closed 场景：

```text
缺 license fail-closed
签名错误 fail-closed
机器不匹配 fail-closed
过期 fail-closed
吊销 fail-closed
```

## 5. Release 包逆向成本门禁

GA release 包必须通过 dist no-source-leak 检查，并阻断：

```text
原始业务 .py 泄露
.pyx 泄露
生成 .c 源码泄露
key / secret / license bundle 误入 release 包
临时构建目录、cache、测试残留进入 dist
local-embedded 默认进入生产包
release_bundle 中 license_file.bundled == true
release_bundle 中 license_file.externalized != true
release_tamper_report.success != true
```

推荐命令：

```powershell
python -B scripts\check_dist_no_source_leak.py <dist_dir> --require-release-metadata --report <report.json>
```

## 6. 本地 GA 证据复验

本仓库提供本地 GA governance smoke，用于复验发布证据闭环、approval key 轮换演练、license-file E2E 和 reverse-cost gate：

```powershell
python -B scripts\non_ocr_ga_release_governance_smoke.py --work-dir .tmp_non_ocr_ga_governance_smoke
```

配套回归：

```powershell
python -B -m pytest -q tests\test_dist_no_source_leakage.py tests\test_non_ocr_ga_release_governance_smoke.py tests\test_non_ocr_release_gate.py tests\test_promotion_artifacts.py tests\test_promotion_bundle.py -p no:cacheprovider
```

## 7. 对外声明边界

允许声明：

```text
避免源代码明文直接暴露
显著提高低成本逆向、篡改和破解门槛
支持任意文件加密保护
支持 Python 代码 native packaging 后保持运行能力
支持 release 证据归档、签名审批、promotion artifact bundle 和 tamper report
```

禁止声明：

```text
绝对不可逆向
绝对不可破解
SO/PYD 等同强保密边界
local-embedded 可抵抗强攻击者
攻击者拿到完整运行环境和密钥后仍无法恢复逻辑
OCR / cross-media 已随非 OCR GA 一起上线
remote-KMS 已随本 GA 正式上线
```
