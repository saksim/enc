# Non-OCR GA Release Governance Plan

日期：2026-06-13
状态：working
目标：把非 OCR 加密 / 代码保护能力从 Mainline Beta 推进到可正式 GA 宣称。

## 一句话结论

下一步不继续扩 OCR。优先把非 OCR 做成可交付、可审计、可回滚、可复验的正式发布能力。

## 顺序

### 1. 发布证据归档上线

目标：每次 release 都有完整证据包，不再只依赖口头或临时测试结果。

必须产出并归档：

```text
release_bundle.json
release_approval.json
release_receipt.json
promotion_evidence.json
promotion_audit_report.json
promotion_artifact_audit_report.json
promotion_run_receipt.json
promotion_artifact_bundle.zip
non_ocr_release_gate_report.json
```

验收口径：

```text
GitHub workflow artifact 可下载
promotion_artifact_bundle.zip 包含必需条目
non_ocr_release_gate_report.passed == true
promotion_audit_report.passed == true
promotion_artifact_audit_report.passed == true
promotion_run_receipt.passed == true
```

### 2. 密钥轮换演练上线

目标：证明发布签名和 approval key 不是摆设，旧 key 必须被拒绝，新 key 必须通过。

必须验证：

```text
rotation_rehearsal=true 时执行旧 approval key 拒绝演练
SOENC_RELEASE_APPROVAL_PREVIOUS_KEY_B64 存在且用于负向验证
rotation_rehearsal_report.status == passed
rotation_rehearsal_report.old_key_rejected == true
```

验收口径：

```text
旧 key release gate 失败
新 key release gate 通过
rotation report 被纳入 promotion_artifact_bundle.zip
```

### 3. 生产 license-file E2E 示例上线

目标：让用户可以照着完成一次真实交付，而不是只看测试名。

示例链路：

```text
源码/文件
  -> protect
  -> build
  -> package
  -> 外置 license-file
  -> 目标机器运行
  -> 错 license / 过期 / 吊销 / 错机器 fail-closed
```

必须覆盖：

```text
SOENC_LICENSE_FILE
SOENC_LICENSE_VERIFY_KEY_B64
SOENC_MACHINE_FINGERPRINT
SOENC_LICENSE_REVOCATION_FILE
license signature
machine binding
expiration
revocation
```

验收口径：

```text
happy path 可运行
缺 license fail-closed
签名错误 fail-closed
机器不匹配 fail-closed
过期 fail-closed
吊销 fail-closed
```

### 4. Release 包逆向成本检查上线

目标：把“无源码泄露”和“无危险调试残留”变成发布硬门禁。

必须阻断：

```text
原始业务 .py 泄露
.pyx 泄露
生成 .c 源码泄露
key / secret / license bundle 误入 release 包
临时构建目录、cache、测试残留进入 dist
local-embedded 默认进入生产包
```

验收口径：

```text
dist no-source-leak check 通过
release_tamper_report.success == true
release_bundle.bundle_contents.license_file.externalized == true
release_bundle.bundle_contents.license_file.bundled == false
```

### 5. 正式 GA 文档上线

目标：把 Mainline Beta 口径升级为 GA 口径，但只在前四项证据完成后进行。

预期新增或更新：

```text
docs/latest/non_ocr_ga_release_manual.md
docs/releases/v0.1.0-ga.md 或 docs/releases/v1.0.0.md
```

GA 文案必须继续避免以下承诺：

```text
绝对不可逆向
绝对不可破解
SO/PYD 等同强保密边界
local-embedded 可抵抗强攻击者
OCR / cross-media 随非 OCR GA 一起上线
```

## 当前推荐施工批次

第一批先做：

```text
1. 发布证据归档上线
2. 密钥轮换演练上线
3. 生产 license-file E2E 示例上线
```

这三项完成后，非 OCR 才从“功能能跑”推进到“能正式交付”。

## 文档流转规则

当前文件属于 `docs/working/`。

完成并验证后：

```text
可操作手册 -> docs/latest/
版本事实 -> docs/releases/
旧计划快照 -> docs/archive/
```
## 本轮实现状态

已新增本地 GA 治理 smoke：

```text
scripts/non_ocr_ga_release_governance_smoke.py
```

它覆盖第一施工批次：

```text
1. 发布证据归档上线：生成 release / promotion / gate / bundle 全套本地证据。
2. 密钥轮换演练上线：使用旧 approval key 复验 release gate 必须失败，并写入 rotation_rehearsal_report.json。
3. 生产 license-file E2E 示例上线：覆盖 happy path、缺 license、签名错误、机器不匹配、过期、吊销 fail-closed。
```

回归测试：

```text
tests/test_non_ocr_ga_release_governance_smoke.py
```

验收命令：

```powershell
python -B scripts\non_ocr_ga_release_governance_smoke.py --work-dir .tmp_non_ocr_ga_governance_smoke
python -B -m pytest -q tests\test_non_ocr_ga_release_governance_smoke.py tests\test_non_ocr_release_gate.py tests\test_promotion_artifacts.py tests\test_promotion_bundle.py -p no:cacheprovider
```

剩余主线仍按顺序推进：

```text
4. Release 包逆向成本检查上线
5. 正式 GA 文档上线
```
