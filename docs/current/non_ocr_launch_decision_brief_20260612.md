# 非 OCR 代码保护线分离上线简明结论（2026-06-12）

## 结论

两条功能线分离上线：

1. **非 OCR 代码保护 / Native Packaging 线**：可作为当前核心上线线，建议进入 Mainline Beta；正式 GA 前需补齐发布治理闭环。
2. **OCR / 跨介质传输线**：暂不并入当前上线承诺，作为独立后续线继续认证与打磨。

## 当前非 OCR 线定位

核心链路：

```text
任意文件加密保护：file -> encrypted artifact -> decrypt/verify
Python 代码保护：.py -> encrypted staging -> .pyd/.so -> import/run
发布闭环：protect -> build -> package -> verify -> release
```

## 已验证证据

```text
非 OCR 主线测试：127 passed, 7 skipped
Code Protection strict native smoke：CODE_PROTECTION_SMOKE_OK
Runtime integrity smoke：RUNTIME_INTEGRITY_SMOKE_PASSED
```

## 上线判断

```text
Mainline Beta：Go
正式 GA：No-Go，需先修复 promotion artifact bundle / live promotion evidence 闭环
OCR 联合上线：No-Go，本轮不纳入非 OCR 线承诺
```

## 产品承诺边界

可以承诺：提高逆向门槛、避免源码明文直接暴露、保护任意文件数据、Python 代码加密后可运行。

不能承诺：绝对不可逆向、绝对不可破解、local-embedded 可抵抗强攻击者、SO/PYD 本身等同强保密边界。

## 当前 P0

1. 非 OCR 线上线文案与功能边界独立于 OCR。
2. 修复发布治理断点：`promotion_bundle.py` 调用缺失的 `normalize_promotion_audit_report_payload`。
3. 补齐正式上线前的 CI / promotion evidence 归档。
