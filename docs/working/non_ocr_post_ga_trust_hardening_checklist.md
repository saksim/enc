# Non-OCR Post-GA Trust Hardening Checklist

日期：2026-06-13
状态：working
边界：本清单只记录 GA 后续信任加固任务，不构成 `latest` 已上线承诺，不改变 `v0.1.0-ga` 的非 OCR 能力边界。

## 目标

把非 OCR GA 发布后的高价值安全与交付工作列清楚，作为后续 working plan 的候选池。任何条目进入实现前，都需要独立施工文档和验收口径。

## 候选主线

### 1. Remote-KMS Enterprise Plan

- 产物：独立 `docs/working/` 施工计划。
- 范围：密钥托管、服务端授权、审计日志、离线降级策略、租户隔离。
- 禁止：在实现前宣称 remote-KMS 已上线。
- 验收：威胁模型、密钥生命周期、回滚/吊销演练、最小可用 PoC 均完成后再进入发布评审。

### 2. 第三方逆向评估模板

- 产物：评估范围模板、证据清单、复测口径、风险分级表。
- 范围：非 OCR 加密/代码保护能力的逆向成本评估。
- 禁止：在第三方报告完成前写成“已通过第三方评估”。
- 验收：模板能覆盖样本、环境、攻击预算、发现项、复测记录。

### 3. 多平台 Native Build Matrix

- 产物：平台矩阵和 CI 构建计划。
- 范围：Windows / Linux / macOS 的 native artifact 构建、签名、hash、来源追踪。
- 禁止：把未覆盖平台写进 latest 手册。
- 验收：每个平台都有 build artifact、checksum、no-source-leak 检查和复验命令。

### 4. 客户侧 License 签发 Runbook

- 产物：客户侧 license 申请、签发、交付、撤销、轮换 runbook。
- 范围：license 文件外置交付和最小权限签发流程。
- 禁止：把人工未验证流程作为生产 SOP。
- 验收：签发成功、错误 license 拒绝、过期/撤销 license 拒绝、审计日志齐全。

### 5. 事故回滚与撤销 License 演练

- 产物：演练脚本、演练报告、发布冻结条件。
- 范围：错误 artifact、错误 license、密钥泄露、证据包污染的回滚路径。
- 禁止：只写流程不做演练。
- 验收：演练报告包含开始时间、执行人、影响范围、回滚证据、复盘项。