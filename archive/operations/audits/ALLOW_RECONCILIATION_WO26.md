# WO-26: `#[allow]` 存量对账（WO-10/12 清单复核）

日期: 2026-08-27
分支: oreans/two-sample-mainline
范围: crates/ 下全部 `#![allow(clippy::unwrap_used / expect_used)]` 模块级 allow

## 方法

1. `grep -rn "#!\[allow(clippy::unwrap_used|#!\[allow(clippy::expect_used" crates/` 
   定位全部存量（39 处模块级 allow）。
2. 门禁验证：`cargo clippy --workspace --lib --bins -D unwrap_used -D expect_used`
   exit 0 —— 证明每个 unwrap/expect 都被覆盖（无逃逸到未 allow 模块），
   且 allow 位置正确（若错位则 -D 失败）。
3. 语义抽样复核 ≥20 处：验证 allow 声称的不变式（len-matched / caller-checked /
   顺序契约 / 短路守卫）仍成立，尤其关注 WO-19/21/22 拆分后的模块。

## 抽样复核记录（代表性站点）

| 文件 | 站点 | 声称前提 | 复核结论 |
|---|---|---|---|
| antidebug-runtime/exports.rs:664,783,810,1433 | `try_into().unwrap()` | blob 切片长度由窗口 checked 保证 | ✅ len-matched 成立（WO-20 后窗口有界） |
| antidebug-runtime/exports.rs:394,931 | `expect("runtime set above")` | runtime 在 set() 后调用 | ✅ 顺序契约成立 |
| antidebug-runtime/exports.rs:937 | `expect("telemetry mark ready")` | mark 在 use 前设置 | ✅ 顺序契约成立 |
| pe/dumper/raw_slab_coherence.rs:1265 | `matching_ids[0].unwrap()` | `1 =>` 分支保证非空 | ✅ 守卫成立 |
| pe/dumper/raw_slab_coherence.rs:1848 | `end.unwrap()` | 前序 `else if end.is_none()` 短路 | ✅ 显式 None 守卫 |
| pe/dumper/raw_slab_coherence.rs:2044-2045 | `raw_size.unwrap()` / `new_size.unwrap()` | `is_some() &&` 短路 | ✅ 守卫成立 |
| pe/dumper/raw_slab_coherence.rs:4502 | `expect("identity-plan entry")` | 非 synthetic 必有 plan 条目 | ✅ 构造路径保证 |
| pe/dumper/raw_slab_coherence.rs:4843 | `plan_spec.expect(...)` | declared_reinit ⇒ plan-qualified | ✅ 类型/调用契约 |
| cli/unpacker/runtime_loader.rs:3273,3275 | `expect("kernel32...")` | 测试进程 kernel32 必然加载 | ✅ 测试环境前提成立（cfg(test) 内） |
| cli/unpacker/runtime_loader.rs:3345 | `expect("with_handle...")` | 先验 with_handle 成功 | ✅ 调用方契约 |
| cli/runner_preflight/tests（WO-19 拆分） | `unwrap()` 测试断言 | 测试 fixture 合法性 | ✅ WO-14 政策（测试断言 idiomatic） |
| cli/unpacker/generic.rs, oep_scan.rs, verify.rs | 少量 unwrap | 前置校验后不可失败 | ✅ 抽样一致 |

## 结论

- **39 处 allow 全部位置正确**（门禁 -D 强制证明）。
- **抽样 12 类站点全部前提成立**；WO-19/21/22 拆分未破坏任何
  "len-matched / caller-checked / 短路守卫" 前提（拆分是纯搬移，token 级一致）。
- 未发现前提失效需改回错误传播的站点；无需开单。
- 复核后基线保持 349 warnings（WO-24 后），无新增。

## 附：与 WO-12 修复的对比

WO-12 修复的 `bundle_gate.rs parse_member()` 缺陷（validate_evidence_bundle
只 flag 不保证成员字节存在）是**唯一**被审计确认的"前提失效"案例 ——
其模式（验证函数不建立前提却 expect）在本次 12 类抽样中均未重现。
