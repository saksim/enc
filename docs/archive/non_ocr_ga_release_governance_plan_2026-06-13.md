# Non-OCR GA Release Governance Plan Archive

日期：2026-06-13
状态：archived
原始工作文档：docs/working/non_ocr_ga_release_governance_plan.md
归档原因：该计划定义的非 OCR GA release governance 主线已经闭环，正式 GA 文档已进入 latest/releases。

## 完成结论

本计划定义的 5 项主线已经完成：

```text
1. 发布证据归档上线
2. 密钥轮换演练上线
3. 生产 license-file E2E 示例上线
4. Release 包逆向成本检查上线
5. 正式 GA 文档上线
```

正式 GA 用户入口：

```text
docs/latest/non_ocr_ga_release_manual.md
docs/releases/v0.1.0-ga.md
```

本归档只记录非 OCR GA 治理计划结果，不声明 OCR / cross-media / remote-KMS 已上线。

## 已落地能力

### 1. 发布证据归档

每次 GA release 必须产出并归档：

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
```

验收口径：

```text
non_ocr_release_gate_report.passed == true
promotion_audit_report.passed == true
promotion_artifact_audit_report.passed == true
promotion_run_receipt.passed == true
```

### 2. 密钥轮换演练

已通过本地 GA governance smoke 证明旧 approval key 必须被拒绝，新 key 必须通过。

验收口径：

```text
rotation_rehearsal_report.status == passed
rotation_rehearsal_report.old_key_rejected == true
rotation report 被纳入 promotion_artifact_bundle.zip
```

### 3. 生产 license-file E2E

已覆盖生产 license-file 交付链路：

```text
源码/文件
  -> protect
  -> build
  -> package
  -> 外置 license-file
  -> 目标机器运行
  -> 错 license / 过期 / 吊销 / 错机器 fail-closed
```

已覆盖 fail-closed 场景：

```text
缺 license fail-closed
签名错误 fail-closed
机器不匹配 fail-closed
过期 fail-closed
吊销 fail-closed
```

### 4. Release 包逆向成本检查

已将 dist no-source-leak 接入 GA governance smoke，并阻断：

```text
原始业务 .py 泄露
.pyx 泄露
生成 .c 源码泄露
key / secret / license bundle 误入 release 包
临时构建目录、cache、测试残留进入 dist
local-embedded 默认进入生产包
release_bundle.bundle_contents.license_file.externalized != true
release_bundle.bundle_contents.license_file.bundled == true
release_tamper_report.success != true
```

### 5. 正式 GA 文档

已落地：

```text
docs/latest/non_ocr_ga_release_manual.md
docs/releases/v0.1.0-ga.md
```

## 复验命令

```powershell
python -B scripts\non_ocr_ga_release_governance_smoke.py --work-dir .tmp_non_ocr_ga_governance_smoke_verify
python -B -m pytest -q tests\test_dist_no_source_leakage.py tests\test_non_ocr_ga_release_governance_smoke.py tests\test_non_ocr_release_gate.py tests\test_promotion_artifacts.py tests\test_promotion_bundle.py -p no:cacheprovider
```

最近复验结果：

```text
NON_OCR_GA_GOVERNANCE_SMOKE_OK
81 passed
non_ocr_ga_governance_smoke_report.passed == true
release_governance.reverse_cost_check_passed == true
release_governance.reverse_cost_check.issues == []
```

## 禁止外溢声明

本归档不允许被解读为以下能力已上线：

```text
绝对不可逆向
绝对不可破解
SO/PYD 等同强保密边界
local-embedded 可抵抗强攻击者
OCR / cross-media 随非 OCR GA 一起上线
remote-KMS 服务端正式上线
```
