# 非 OCR 代码保护线上线策略与 GPT5.5 施工交接（2026-06-12）

## 1. 结论

非 OCR 代码保护线独立上线，作为当前主线产品推进。

```text
Mainline Beta：Go
正式 GA：No-Go，需先补齐发布治理与生产默认安全策略
OCR / 跨介质线：本轮不纳入上线承诺
```

核心产品承诺：

```text
任意文件：可加密、可解密、可校验完整性。
Python 代码：可加密保护后编译为 .pyd/.so，并保持 import/run 功能。
安全目标：不承诺绝对不可逆向；目标是避免源码明文暴露，并显著提高逆向、破译、篡改成本。
```

## 2. 产品边界

### 当前上线线

```text
protect -> build -> package -> verify -> release
```

主要模块：

```text
encryption_helper.py        # 源码选择、片段加密、staging、manifest、release helpers
decryption_helper.py        # 运行时解密、license lookup、compile/exec、integrity checks
py2_linux_rec_opera.py      # Cython/native packaging 到 .pyd/.so
enc2sop/keys/*              # local/license/remote-kms key providers
enc2sop/protect/*           # hardening 与 dist no-source-leak
enc2sop/cli.py              # protect/build/package/verify/release CLI
```

### 本轮非目标

```text
OCR / QR / cross-media 可靠传输
真实拍照、打印扫描、OCR-only 认证
承诺绝对防逆向、绝对防破解
将 local-embedded 描述为强安全模式
```

## 3. 已验证状态

最近验证证据：

```text
非 OCR 主线测试：127 passed, 7 skipped
Code Protection strict native smoke：CODE_PROTECTION_SMOKE_OK
Runtime integrity smoke：RUNTIME_INTEGRITY_SMOKE_PASSED
```

已成立能力：

```text
.py -> encrypted staging -> .pyd/.so -> clean import/run
dist no-source-leak 检查
license-file 外置交付
license 过期、机器绑定、签名、吊销机制
runtime 替换 / manifest 篡改 / digest mismatch fail-closed
release receipt / release tamper report
cm/transport help 与 code-protection 重依赖解耦
```

## 4. 安全策略决策

### 决策 1：生产默认使用 license-file

选择：

```text
生产 / Beta 默认：license-file
开发 / demo 显式模式：local-embedded + --dev-insecure-ok
高安全商业版：remote-kms
```

理由：

```text
local-embedded 用户体验最好，但密钥随包分发，只能提高低成本逆向门槛。
license-file 能外置密钥，并支持签名、机器绑定、过期、吊销，是 Mainline Beta 合理默认。
remote-kms 安全上限最高，但需要服务端体系，作为 Enterprise 阶段推进。
```

### 决策 2：上线文案只承诺提高成本

允许承诺：

```text
避免源码明文直接暴露
显著提高逆向和破译成本
保护任意文件数据
Python 代码保护后保持运行能力
```

禁止承诺：

```text
绝对不可逆向
绝对不可破解
SO/PYD 等同强保密边界
local-embedded 可抵抗强攻击者
攻击者拿到完整运行环境和密钥后仍无法恢复逻辑
```

## 5. 分阶段路线

### Phase 1：Mainline Beta（当前主线）

目标：非 OCR 线单独上线。

必须保持：

```text
keys.mode = license-file
bundle_license = false
require_manifest_signature = true
require_release_approval = true
runtime integrity checks = on
dist no-source-leak = required
```

验收命令：

```powershell
python -B -m pytest -q tests\test_encryption_helper.py tests\test_decryption_helper.py tests\test_key_provider.py tests\test_soenc_config.py tests\test_soenc_cli.py tests\test_toolchain_profile.py tests\test_dist_no_source_leakage.py tests\test_protect_hardening.py tests\test_runtime_integrity_smoke.py tests\test_code_protection_smoke.py

D:\code_environment\anaconda_all_css\py312\python.exe -B scripts\smoke_code_protection.py --python-exe D:\code_environment\anaconda_all_css\py312\python.exe

python -B scripts\smoke_runtime_integrity.py
```

### Phase 2：正式 GA 前 P0

必须修复：

```text
enc2sop/promotion_bundle.py 当前调用缺失函数：
promotion_audit.normalize_promotion_audit_report_payload
```

验收命令：

```powershell
python -B -m pytest -q tests\test_promotion_bundle.py
python -B -m pytest -q tests\test_release_promotion_workflow.py tests\test_promotion_evidence.py tests\test_promotion_bundle.py
```

必须补齐：

```text
live CI / promotion evidence
protected branch evidence
environment reviewer evidence
required secret evidence
promotion artifact bundle archive
```

### Phase 3：Security Hardening Release

建议施工：

```text
生产配置默认拒绝 local-embedded，除非显式 --dev-insecure-ok
license-file 默认要求签名
native-only runtime 作为推荐生产模式
release 包必须强制 no-source-leak
manifest signature 默认打开
hardening profile 默认 balanced，企业版 strict
```

### Phase 4：Enterprise / High-Security

建议施工：

```text
remote-kms 实体服务
短期 unwrap token
服务端审计日志
设备绑定与吊销
调用频率限制
异常行为封禁
多平台 native build matrix
```

## 6. GPT5.5 后续施工优先级

### P0

```text
1. 修复 promotion_bundle.py 缺失 normalize_promotion_audit_report_payload 问题。
2. 将生产默认文档与配置收敛到 license-file。
3. 明确 local-embedded 只允许 dev/demo/anti-casual。
4. 跑通 release/promotion/bundle 验收链路。
```

### P1

```text
1. 增加生产配置模板：soenc.production.toml。
2. 增加一键 Mainline Beta smoke 脚本。
3. 增加 release 包逆向成本检查清单。
4. 补充 license 签名、机器绑定、吊销的端到端示例。
```

### P2

```text
1. remote-kms 服务端 POC。
2. 企业版审计与设备风险策略。
3. 多平台构建产物矩阵。
4. 第三方逆向评估报告模板。
```

## 7. 质量门禁

任何后续 GPT5.5 施工不得破坏以下门禁：

```text
cm/transport --help 不得导入 code-protection 重依赖
release dist 不得包含原始 .py/.pyx/.c 源码泄露
license-file 默认不得 bundle license
runtime integrity 失败必须 fail-closed
local-embedded 必须带 insecure 标记和显式 opt-in
```

## 8. 回滚策略

```text
配置回滚：从 strict/balanced 回退到当前 license-file beta 默认，但不得回退到生产默认 local-embedded。
功能回滚：保留 protect/build/package/verify/release 旧 CLI 兼容。
发布回滚：release receipt / tamper report 任一失败即禁止推广。
安全回滚：remote-kms 失败不得 fallback 到 local-embedded。
```

## 9. 最终上线口径

推荐对外口径：

```text
enc2sop 非 OCR 代码保护线支持任意文件加密与 Python 代码 native packaging 保护。
它通过外置 license、native packaging、运行时完整性检查和 release 校验，显著提高源码泄露、篡改和低成本逆向的门槛。
该能力不宣称绝对不可逆向；高安全场景建议使用 license-file 签名/机器绑定或 remote-kms 模式。
```
