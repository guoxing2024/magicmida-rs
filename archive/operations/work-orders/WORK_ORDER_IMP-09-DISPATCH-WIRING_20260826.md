# WORK ORDER — IMP-09-DISPATCH-WIRING: LIVE GATE CONTROLLED WIRING (方案1)

**签发**: Hermes 总审计，owner 批准（方案 1：环境门控接线）
**日期**: 2026-08-26
**性质**: 小型生产实现单——把已审计的桥接经环境门控接进两处生产构造点
**基线**: HEAD `ba6ab40`（attempt_002 BLOCKED 报告已入库）
**前置**: walker_dispatch.rs 已审计 PASS（9b05abc）；本单只做接线，不改桥语义

## 1. 背景

GTO-H6-LIVE-1 attempt_002 因结构性缺口 BLOCKED：桥接实现存在且审计通过，
但两处生产 `AntidebugStageOptions` 构造点恒传 `walker_dispatch: None`，
execute 门必然 NotImplemented；且 `MIDA_GTO_LIVE_AUTHORIZED` 无任何代码
读取点。本单补上受控接线。

## 2. 门控设计（核心契约）

新增集中式门控函数（建议放 walker_dispatch.rs 内）:

```rust
/// LIVE dispatch gate. Returns true only when BOTH hold:
///   1. MIDA_GTO_NO_BYPASS == "1"            (observation discipline on)
///   2. MIDA_GTO_LIVE_DISPATCH == "1"        (explicit live unlock, set by
///      the signed LIVE work order's execution window, cleared after)
pub fn live_dispatch_gate() -> bool { ... }
```

规则:
- **两个变量必须同时为 "1"** 才解锁；任一缺失/其他值 → false;
- `MIDA_GTO_LIVE_AUTHORIZED` 废弃不用（无读取点的历史名，避免混淆）;
- 接线点写法（两处同款）:

```rust
walker_dispatch: {
    if walker_dispatch::live_dispatch_gate() {
        // 构造走 §D 双 sealed 路径; 任一 carrier 缺失 -> None (fail-closed)
        ...construct... .map(|b| Box::new(b) as Box<dyn WalkerDispatchBridge>)
    } else {
        None
    }
},
```

## 3. 硬约束

1. 桥构造必须沿用 `RemoteWalkerExecuteBridge/WalkerDispatchBridgeImpl::new`
   的双 sealed 交叉校验，禁止绕过；
2. post-attach 与 CREATE_PROCESS 两处都要接；构造失败（carrier 缺失）
   → None → 既有 NotImplemented fail-closed 分支保留不动；
3. offline（门关）行为与现状字节级等价：None 进、NotImplemented 出；
4. 不改 R5-R2/R3/R4 冻结语义、不改 runner_preflight.rs、不改桥本身。

## 4. 测试要求

在既有 T1-T12 之上追加（T13-T16）:

- T13: gate 关（两变量缺失/只其一）→ options.walker_dispatch == None;
- T14: gate 开（两变量均 "1"）+ carriers 完整 → Some(bridge) 且
  cross_check 通过的构造成功；carriers 缺失 → None;
- T15: gate 开 + 交叉校验必败载体（mismatch VA）→ 构造 None /
  dispatch 返回 BAD_PARAMS（证明门开也不能跳过权威链）;
- T16: 全部 16 测试 offline 可重跑（env 操作用串行锁防并行污染，
  参考既有 INSTALL_LOCK 模式）。

## 5. 交付

1. 生产接线 diff + T13-T16 测试全绿 + workspace 全量统计;
2. 设计文档 §D 更新（接线现状从"deferred"改为"wired behind env gate"，
   注明门控变量名与语义）; HANDOFF_PROMPT 同步更新授权变量名;
3. 出口门 ini:

```ini
DISPATCH_WIRING = PROVEN
LIVE_GATE_ENV_CONTROLLED = true
OFFLINE_DEFAULT_NONE = true (gate 关时与基线行为一致)
T13_T16 = ALL_PASS
WORKSPACE_GREEN = true
R5_SEMANTICS_UNCHANGED = true
LIVE_AUTHORIZED = false (本单仍不执行实弹)
```

Correction 上限 = 1；证据从简。
