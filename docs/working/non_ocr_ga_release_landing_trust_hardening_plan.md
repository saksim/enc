# Non-OCR GA Release Landing & Trust Hardening Plan

日期：2026-06-13
状态：working
前置条件：`docs/archive/non_ocr_ga_release_governance_plan_2026-06-13.md` 已归档，非 OCR GA governance 主线已闭环。

## 一句话结论

下一轮不扩 OCR，也不把 remote-KMS 当作已上线能力。优先把“本地可复验 GA”推进为“仓库级真实发布、可下载证据、可重复发布、可持续信任”的工程闭环。

## 目标边界

本轮只服务非 OCR GA 后续主线：

```text
真实 GitHub release / tag / artifact 闭环
生产 release runbook 与一键复验入口
GA 后 CI 质量门禁
证据包完整性与可下载性
发布后信任硬化
```

本轮不包含：

```text
OCR / QR / cross-media 新能力上线
remote-KMS 服务端实现或上线声明
第三方逆向评估报告落地
重写加密核心算法
扩大 GA 对外承诺
```

如果后续要做以上能力，必须先新建独立 working plan 并确认范围。

## 顺序

### 1. 真实 GitHub Release / Tag / Artifact 闭环

目标：把本地 GA smoke 证据升级为仓库级发布事实。

必须落地：

```text
GA tag 规则
GitHub Actions release workflow 产出 promotion_artifact_bundle.zip
release notes 引用 docs/releases/v0.1.0-ga.md
workflow artifact 可下载
release artifact checksum 可复验
```

验收口径：

```text
git tag 指向 GA release commit
GitHub workflow run 成功
promotion_artifact_bundle.zip 可从 workflow 或 release 下载
bundle_manifest.json 记录 sha256
本地下载后可复验关键 JSON passed=true
```

### 2. 生产 Release Runbook 与一键复验入口

目标：减少每次发布时的人为操作错误。

必须落地：

```text
docs/latest/non_ocr_ga_release_runbook.md
scripts 或命令入口复用 non_ocr_ga_release_governance_smoke
明确 release 前 / release 中 / release 后步骤
明确失败回滚条件
```

验收口径：

```text
新操作者按 runbook 能完成一次 dry-run
所有命令可以复制执行
失败条件和停止条件明确
```

### 3. GA 后 CI 质量门禁

目标：把 GA 的关键复验从人工记忆变成 CI gate。

必须纳入：

```text
non_ocr_ga_release_governance_smoke
release gate
promotion artifact audit
promotion bundle audit
dist no-source-leak --require-release-metadata
license-file E2E fail-closed
```

验收口径：

```text
CI 任一关键 gate 失败则阻断 release
CI 报告中能看到 reverse_cost_check_passed
CI 报告中能看到 license_file_e2e_passed
```

### 4. 证据包可审计性增强

目标：让证据包不仅存在，而且便于审计和复验。

必须落地：

```text
artifact manifest
sha256 清单
必需条目缺失时 fail-closed
证据 JSON schema/version 字段检查
归档路径和保留周期说明
```

验收口径：

```text
缺任一必需证据文件时审计失败
checksum 不匹配时审计失败
schema/version 缺失时审计失败
```

### 5. 发布后信任硬化清单

目标：把 GA 后仍未做的高价值安全工作列清楚，但不误写成已上线能力。

候选项：

```text
remote-KMS Enterprise plan
第三方逆向评估模板
多平台 native build matrix
客户侧 license 签发 runbook
事故回滚与撤销 license 演练
```

验收口径：

```text
只形成后续 plan / checklist
不进入 latest 的已上线承诺
不改变 v0.1.0-ga 的能力边界
```

## 当前推荐施工批次

第一批先做：

```text
1. 真实 GitHub Release / Tag / Artifact 闭环
2. 生产 Release Runbook 与一键复验入口
3. GA 后 CI 质量门禁
```

这三项完成后，非 OCR GA 才从“本地证据闭环”推进到“仓库发布事实闭环”。

## 文档流转规则

当前文件属于 `docs/working/`。

完成并验证后：

```text
可操作 runbook -> docs/latest/
版本事实 -> docs/releases/
旧计划快照 -> docs/archive/
```

## 起始验收命令

```powershell
python -B scripts\non_ocr_ga_release_governance_smoke.py --work-dir .tmp_non_ocr_ga_governance_smoke_verify
python -B -m pytest -q tests\test_dist_no_source_leakage.py tests\test_non_ocr_ga_release_governance_smoke.py tests\test_non_ocr_release_gate.py tests\test_promotion_artifacts.py tests\test_promotion_bundle.py -p no:cacheprovider
```
