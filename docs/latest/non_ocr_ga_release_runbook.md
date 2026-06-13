# Non-OCR GA Release Runbook

发布日期：2026-06-13
状态：latest
适用范围：非 OCR GA release landing、证据包复验、GitHub artifact / release artifact 发布。

## 1. 发布前检查

确认本次发布仍只覆盖非 OCR GA 主线：

```text
protect -> build -> package -> verify -> release
```

不得把以下能力写成本次已上线：

```text
OCR / QR / cross-media 新能力上线
remote-KMS 服务端正式上线
第三方逆向评估报告完成
绝对不可逆向或绝对不可破解
```

## 2. 本地 dry-run

先运行本地 GA governance smoke：

```powershell
python -B scripts\non_ocr_ga_release_governance_smoke.py --work-dir .tmp_non_ocr_ga_governance_smoke_verify
```

再运行 GA landing gate：

```powershell
python -B scripts\non_ocr_ga_landing_gate.py --smoke-report .tmp_non_ocr_ga_governance_smoke_verify\non_ocr_ga_governance_smoke_report.json --report .tmp_non_ocr_ga_governance_smoke_verify\non_ocr_ga_landing_gate_report.json
```

必须看到：

```text
NON_OCR_GA_GOVERNANCE_SMOKE_OK
NON_OCR_GA_LANDING_GATE_OK
license_file_e2e_passed=True
reverse_cost_check_passed=True
```

## 3. 回归测试

```powershell
python -B -m pytest -q tests\test_non_ocr_ga_landing_gate.py tests\test_non_ocr_ga_release_governance_smoke.py tests\test_dist_no_source_leakage.py tests\test_non_ocr_release_gate.py tests\test_promotion_artifacts.py tests\test_promotion_bundle.py -p no:cacheprovider
```

## 4. GitHub Actions 证据闭环

使用 workflow：

```text
.github/workflows/non_ocr_ga_landing.yml
```

推荐触发方式：

```text
workflow_dispatch: dry-run artifact upload
push tag v*-ga 或 v*-ga.*: GA tag artifact upload
```

workflow 必须产出 artifact：

```text
non_ocr_ga_governance_smoke_report.json
non_ocr_ga_landing_gate_report.json
promotion_artifact_bundle.zip
release_bundle.json
release_approval.json
release_receipt.json
release_tamper_report.json
promotion_evidence.json
promotion_audit_report.json
promotion_artifact_audit_report.json
promotion_run_receipt.json
rotation_rehearsal_report.json
```

## 5. GitHub Release Artifact 发布

如果需要把证据包上传到 GitHub Release，先确认 tag 已存在：

```powershell
git tag --list v0.1.0-ga
git rev-parse v0.1.0-ga^{}
```

然后运行 `non-ocr-ga-landing` workflow，并设置：

```text
publish_release_artifacts = true
release_tag = v0.1.0-ga
```

workflow 不会创建 git tag。tag 缺失时必须 fail-closed。

## 6. 下载后复验

下载 workflow artifact 或 GitHub Release artifact 后，重新运行：

```powershell
python -B scripts\non_ocr_ga_landing_gate.py --smoke-report <downloaded>\non_ocr_ga_governance_smoke_report.json --promotion-bundle <downloaded>\promotion_artifact_bundle.zip --report <downloaded>\non_ocr_ga_landing_gate_report.replay.json
```

如果 bundle sha256、manifest entry sha256、关键 JSON schema、passed 字段或 rotation rehearsal 不满足要求，命令必须失败。


## 7. 证据归档与保留周期

证据包归档路径以 GitHub Actions artifact 为主，以 GitHub Release artifact 为长期发布事实：

```text
Workflow artifact: non-ocr-ga-landing-<run_id>-attempt-<run_attempt>
Workflow retention: 90 days
GitHub Release artifact: attached to v0.1.0-ga or the selected GA tag
Release retention: retained while the GitHub Release exists
Local replay path: downloaded artifact directory chosen by the operator
```

`non_ocr_ga_landing_gate_report.json` 必须包含 `artifact_manifest.sha256` 清单。下载后复验时，任何必需证据缺失、manifest 未声明 zip 条目、sha256 不匹配、关键 JSON schema/version 缺失，均视为发布证据不可用并停止发布。

## 8. 停止条件

出现任一情况，停止发布：

```text
NON_OCR_GA_GOVERNANCE_SMOKE_FAILED
NON_OCR_GA_LANDING_GATE_FAILED
promotion_artifact_bundle.zip 缺失
bundle_manifest.json 缺失或 sha256 不匹配
license_file_e2e_passed != true
reverse_cost_check_passed != true
rotation_rehearsal_passed != true
release_tamper_report.success != true
```

## 9. 回滚口径

文档或证据发布失败时，只回滚发布动作和 artifact，不回滚已验证的代码保护能力。

```text
删除错误 GitHub Release artifact
重新运行 workflow_dispatch dry-run
确认 landing gate 通过后再发布 artifact
```
