# WORK ORDER — IMP-09-DISPATCH-BRIDGE-IMPL (target-side WalkerExecute 桥接实现)

**签发**: Hermes 总审计，owner 授权
**日期**: 2026-08-25
**性质**: 生产实现单
**基线**: 当前 HEAD（设计卡文档已入库或随本卡同提交）
**设计依据**: `docs/IMP09_DISPATCH_BRIDGE_DESIGN_20260825.md`（已审计签收）——§A-D 接口草案 + T1-T12 测试矩阵

## 1. 目标

按设计文档落地 authorized target-side WalkerExecute dispatch bridge：

1. 实现 `WalkerDispatchBridge` trait 的生产实现（§A），dispatch thunk 字节
   按冻结草案（§B）；
2. 观测记录 `WalkerDispatchObservation` 挂入 walker evidence sidecar（§C）;
3. controller 侧接线（§D）——**但 LIVE 解锁门保持关闭**：
   - 生产路径 `options.walker_dispatch` 仍恒 `None`（mod.rs:1221-1227 /
     mod.rs:785-790 两处接线不动），
   - 桥实现本身交付为可构造类型，唯一解锁条件 = owner 签发 LIVE-4 后由
     总审计另行授权的显式构造点；offline 下任何测试/生产路径都不得把它
     接进 controller；
   - `execute_walker_production()` 的 NotImplemented fail-closed 分支保留。

## 2. 权威链硬约束（违反即 FAIL）

- params_va / section1_va / 双 digest / module_base / export RVA / profile /
  nonce / 候选 VA 全部来自既有 sealed carrier，零 open-caller 字符串、零魔法值；
- 远程线程入口必须双 sealed 交叉校验：`remote_va == module_base + file_rva`
  （两侧来源不同 carrier），不匹配 fail-closed 拒绝 dispatch；
- 注入失败语义严格按设计 §Q4：会话未建立 → teardown `Released`+空账本；
  已建立但 dispatch 失败 → 正常 teardown + T1 分离上报。

## 3. 测试要求

完成设计文档 §5 测试矩阵 T1-T12 全项（含注入失败、digest mismatch、
未授权拒绝、thunk 字节冻结校验、观测字段完整性）。全部离线确定性，
`offline_mock=true`。

## 4. 必须交付

1. 生产代码 + T1-T12 测试 + caller graph 更新（如实际落点与设计有偏差,
   文档同步更正并标注）;
2. raw evidence 从简一套 + 出口门 ini 实测值;
3. 全 workspace `cargo test` 统计（这是 LIVE-4 授权前置条件的最后验证）;
4. fmt: 触及文件 clean,全仓 NOT_PASS 如实记录;
5. 声明: `live_authorized=false` / `protected_sample=NOT_AUTHORIZED`。

## 5. 禁止

- 接入 live dispatch 执行任何真实目标进程; protected sample 禁触;
- 改 runner_preflight.rs / R5-R2/R5-R3/R5-R4 冻结语义（round_flags 布局、
  生命周期窗口顺序、teardown 账本规则）;
- 把桥接进任何 offline 可达的生产路径（LIVE 门必须只在 owner 授权后打开）;
- mock 冒充生产 thunk; silent retry。
- Correction 上限 = 1; 证据从简。

## 6. 出口门

```ini
DISPATCH_BRIDGE_IMPL = PROVEN
THUNK_BYTES_FROZEN = PROVEN
AUTHORITY_MATRIX_ENFORCED = true
OFFLINE_TESTS_T1_T12 = ALL_PASS
LIVE_GATE_STILL_CLOSED = true
WORKSPACE_TEST_GREEN = true (除既有环境性失败,逐项列出并附基线证据)
ADR7_GATES_UNCHANGED = true
LIVE_AUTHORIZED = false
PROTECTED_SAMPLE = NOT_AUTHORIZED
```
