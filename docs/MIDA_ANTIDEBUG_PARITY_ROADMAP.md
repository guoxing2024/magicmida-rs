# MIDA 反反调试对等路线图（WO-902）

**依据**: WO-901 差距审计（8 缺口，Top-4 致命）+ owner 决策（自研为准，弃 ScyllaHide）
**性质**: 设计文档（零实现）；实施须另批
**执行**: 唯一 worker · 2026-08-22
**状态**: DESIGN — 待总指挥批准后拆单

---

## 一、分阶段计划（致命缺口优先）

### Phase 1 — 致命对等（Top-1/2：NtGlobalFlag + 堆标志）

| 项 | 值 |
|---|---|
| 技术项 | PEB.NtGlobalFlag 清理 + PEB 堆标志（HeapFlags/HeapForceFlags）清理 |
| 落点模块 | antidebug-runtime/surfaces/proc.rs（新增 AD-PROC-004/005）+ themida/antiantidebug/handlers.rs |
| 证据契约 | mida.antidebug-probe-result/v1（original/effective/restoration 三态记录）+ runtime-attestation 更新 |
| 离线验证 | PEB 布局单测（x64 偏移 authority：NtGlobalFlag=0xBC）；标志位模型纯函数测试 |
| 完成判据 | 双 surface install/restore 单测绿；NtGlobalFlag 读取确认 = 0x0（非 debugger 基线） |
| 工作量 | **M**（~2-3d） |

### Phase 2 — 高优先补强（Top-3/4：CRDP + 时序）

| 项 | 值 |
|---|---|
| 技术项 | CheckRemoteDebuggerPresent 对抗 + 时序攻击掩盖（RDTSC/QPC 补丁或掩盖） |
| 落点模块 | themida/antiantidebug/handlers.rs（CRDP 分支）+ 新 timings.rs（时序探测） |
| 证据契约 | mida.antidebug-observation/v1（探测输入/输出/置信度） |
| 离线验证 | CRDP 调用模型 mock 测试；时序探测确定性测试（固定时钟输入） |
| 完成判据 | CRDP 返回伪造值测试绿；时序探测在固定基准下确定性 |
| 工作量 | **M**（~2-3d） |

### Phase 3 — 纵深防御（NtQueryObject + OutputDebugString + 驱动名）

| 项 | 值 |
|---|---|
| 技术项 | NtQueryObject(DebugObject 枚举) 对抗 + OutputDebugString 对抗 + 驱动名检查 |
| 落点模块 | themida/antiantidebug/（新 queries.rs）+ kifast.rs 扩展 |
| 证据契约 | mida.antidebug-observation/v1 |
| 离线验证 | syscall number 解析测试（复用 kifast 既有模式） |
| 完成判据 | 各分支处理函数单测绿；无回归（2279+ 基线） |
| 工作量 | **S**（~1-2d） |

### Phase 4 — Oreans 接线（双轨切换）

| 项 | 值 |
|---|---|
| 技术项 | 替换 themida/lib.rs 的 inject_scylla_hide 为自研栈激活开关 |
| 落点模块 | themida/lib.rs + mod.rs（接线）+ packers/themida/plugin.rs（profile 驱动） |
| 证据契约 | mida.antidebug-profile/v1（profile 决定 legacy/自研）+ runtime-attestation |
| 离线验证 | 双轨切换单测（profile=legacy → 原路径；profile=self → 新路径）；回滚开关测试 |
| 完成判据 | CI 双 lane 绿；Oreans 两样本门 17/17 PASS 不回归；ScyllaHide 二进制不再被引用 |
| 工作量 | **M**（~2-3d） |

## 二、Oreans 双轨切换设计

### 架构

    profile (mida.antidebug-profile/v1)
      |-- legacy: 现路径（ScyllaHide pre-injection，仅过渡期）
      '-- self:   自研栈（ADR stack: antidebug 控制器 + antidebug-runtime surfaces）

    切换开关: MIDA_ANTIDEBUG_MODE=legacy|self（默认 legacy 直至 Phase 1-3 全部绿）
    回滚开关: MIDA_ANTIDEBUG_ROLLBACK=1（任何实弹异常 → 强制 legacy）

### 原则

- **双轨期**: Phase 1-3 完成后并行运行（CI 双轨），Oreans 门为仲裁者；
- **对等覆盖达成后替换**: 差距审计 9 项覆盖（5 已有 + 4 补齐）→ ScyllaHide 注入移除；
- **证据契约贯穿**: 每次激活产 runtime-attestation 证据，可审计；
- **洁净室不变**: 只对照公开技术清单做覆盖矩阵，不参考 ScyllaHide 源码。

## 三、明确不做项（红线）

| 项 | 理由 |
|---|---|
| DRx 硬件断点对抗 | 授权红线（WO-902 工单明确）；核心调试器既有 DRx 语义除外 |
| 内核态手段 | 用户态边界（本项目定位）；不做驱动 |
| 任何 bypass 语义 | 与 GTO/Oreans 门纪律冲突；不做语义修复 |
| 保护器解密算法复现 | 终局结论（dump-route TERMINAL）；超出范围 |

## 四、工作量分级估算（S/M/L）

| 阶段 | 内容 | 工作量 | 拆单建议 |
|---|---|---|---|
| Phase 1 | NtGlobalFlag + 堆标志 | M（2-3d） | 1 单 |
| Phase 2 | CRDP + 时序掩盖 | M（2-3d） | 1 单 |
| Phase 3 | NtQueryObject + OutputDebugString + 驱动名 | S（1-2d） | 1 单（可并入 Phase 2） |
| Phase 4 | Oreans 接线（双轨 + 回滚） | M（2-3d） | 1 单（依赖 1-3） |
| **合计** | | **~7-11d** | 4 单 |

## 五、依赖与风险

- **依赖**: Phase 4 依赖 1-3 全部完成 + Oreans 门回归通过；
- **风险 1（低）**: NtGlobalFlag 偏移（0xBC x64）跨版本漂移 → authority 常量 + 运行时校验；
- **风险 2（中）**: 时序掩盖对惰性解密观测的影响 → 观测通道独立于时序补丁；
- **风险 3（低）**: 双轨期 CI 负担 → 仅 Oreans 门跑双轨，其他测试单轨。

## 六、结论

- **最小对等集**: Phase 1（Top-1/2 致命缺口）→ 对 SecureEngine 检测面覆盖完整；
- **替换条件**: Phase 1-3 绿 + Oreans 17/17 不回归 → Phase 4 接线 + 移除 ScyllaHide；
- **干净终局**: 外部依赖清零，全部自研（洁净室纪律全程）。
