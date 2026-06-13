# 非 OCR release 包逆向成本检查清单（2026-06-12）

本清单只服务 `docs/latest/non_ocr_code_protection_launch_strategy.md` 中的非 OCR 代码保护线：`protect -> build -> package -> verify -> release`。它用于 Mainline Beta / GA 前 release 包评审，目标是确认“显著提高逆向、破译、篡改成本”，不承诺绝对不可逆向、绝对不可破解。

## 0. 适用边界

- 适用：任意文件加密、Python 代码保护、native packaging、license-file 外置交付、release/promotion 治理证据。
- 不适用：OCR / QR / cross-media、真实拍照扫描认证、remote-kms 服务端 POC、第三方逆向评估报告。
- 禁止口径：SO/PYD 等同强保密边界；local-embedded 可抵抗强攻击者；攻击者拿到完整运行环境和密钥后仍无法恢复逻辑。

## 1. 必过门禁

| 检查项 | 合格标准 | 证据 |
| --- | --- | --- |
| key mode | 生产/Beta 配置为 `license-file` | `soenc.production.toml` 或 release 配置 |
| license 外置 | `bundle_license = false`，release 包不内置生产 license | `build_manifest.json`、release 包内容 |
| license 签名 | license-file 使用 HMAC 签名，运行时要求 `SOENC_LICENSE_VERIFY_KEY_B64` | license payload、manifest `license_signature_required` |
| 机器绑定 | 需要绑定时运行时要求 `SOENC_MACHINE_FINGERPRINT`，错误机器 fail-closed | license payload、E2E smoke |
| 吊销 | 运行时支持 `SOENC_LICENSE_REVOCATION_FILE`，命中 revoked id fail-closed | revocation JSON、E2E smoke |
| manifest signature | `manifest signature` 必须存在且校验失败 fail-closed | `build_manifest.json`、manifest smoke |
| runtime integrity | `runtime integrity` 打开，runtime 替换 / digest mismatch fail-closed | runtime integrity smoke |
| dist no-source-leak | `dist no-source-leak` 必须通过，release dist 不包含原始 `.py/.pyx/.c` 源码 | no-source-leak 测试、tamper report |
| native package | 生产推荐 `.pyd/.so` native-only runtime loader | strict native smoke |
| release approval | `require_release_approval = true`，release receipt / tamper report 任一失败禁止推广 | `release_approval.json`、`release_receipt.json` |
| promotion archive | `promotion_artifact_bundle.zip` 必须归档，且 audit report 为 passed | promotion workflow artifact |

## 2. 人工抽查

1. 解压 release 包，确认没有业务源码明文直接暴露；允许的 bootstrap 文件必须能解释用途。
2. 检查 `build_manifest.json` 中 `key_management.mode == license-file`、`bundle_license == false`、`license_signature_required == true`。
3. 检查 license payload 中 `signature`、`machine_binding`、`revocation` 字段完整。
4. 在缺少 `SOENC_LICENSE_VERIFY_KEY_B64`、错误 `SOENC_MACHINE_FINGERPRINT`、命中 `SOENC_LICENSE_REVOCATION_FILE` 三种场景下分别确认 fail-closed。
5. 检查 promotion 产物包含 `release_bundle.json`、`release_approval.json`、`release_receipt.json`、`promotion_evidence.json`、`promotion_audit_report.json`、`promotion_artifact_bundle.zip`。
6. 检查对外文案只描述“提高逆向成本 / 避免源码明文直接暴露”，不得写成绝对防逆向。

## 3. local-embedded 降级边界

- `local-embedded` 仅允许开发、demo、anti-casual 场景。
- CLI 必须显式 `--dev-insecure-ok` 才能使用。
- 生产/Beta release 审查中发现 `local-embedded` 默认配置时，必须阻断发布并回滚到 license-file。

## 4. 推荐验收命令

```powershell
python -B -m pytest -q tests\test_encryption_helper.py tests\test_decryption_helper.py tests\test_key_provider.py tests\test_soenc_config.py tests\test_soenc_cli.py tests\test_toolchain_profile.py tests\test_dist_no_source_leakage.py tests\test_protect_hardening.py tests\test_runtime_integrity_smoke.py tests\test_code_protection_smoke.py
python -B -m pytest -q tests\test_release_promotion_workflow.py tests\test_promotion_evidence.py tests\test_promotion_bundle.py tests\test_promotion_artifacts.py
powershell -ExecutionPolicy Bypass -File scripts\mainline_beta_smoke.ps1
```
