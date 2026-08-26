# GTO-H5-RESOLVER-CAUSAL-PROOF-1-AUDIT-CORRECTION-1 — 完成报告

## 一、审计发现全部接受

1. **P0 偏移错误**：candidate e_lfanew=0x80 → DD base=0x108, IMPORT=0x110, IAT=0x168, EXPORT=0xE8。
   原 F3 监视了 0x140000108(EXPORT)+0x140000168(IAT) = EXPORT+IAT；F4 把 Import 值写进了 EXPORT 字段。
2. **F3/F4 无效**："resolver 不读 Import DD"和"Import+IAT 回填阴性"均不成立；run4/5/6 重新标记为 **EXPORT+IAT mutation negative**。
3. **v2 根因保持 PENDING**（原"import-dir 机制被否决"声明无效）。
4. 其他：run 数 10>6、item4 缺 Import-only/IAT-only、item5/8 PENDING、run3 断点地址错(0x142c1cec3 vs 0x142c1d6c3)、F6 过度声明（只证明 r9 依赖栈槽选择，TLS0→resolver 寄存器/栈/调用链两目标一致）。

## 二、6 个修正 session（正确偏移，离线计算）

| # | 内容 | 结果 |
|---|---|---|
| 1 | 正确 DD watch（IMPORT @0x140000110 + IAT @0x140000168） | **无 reader 命中** |
| 2 | Import-only 回填（确认生效 0x17dc3e8/0x154） | **仍 AV 0x142934089** |
| 3 | IAT-only 回填（确认生效 0x159f000/0x1190） | **仍 AV** |
| 4 | Import+IAT 组合（正确偏移） | **仍 AV** |
| 5 | EXPORT-only 负控制 | **仍 AV** |
| 6 | pre-loader patched copy（外部副本，全部 DD 恢复 protected，hash e623c41b…） | **仍 AV** |

## 三、结论

- **DataDirectory 机制被有效否定**（这次偏移正确）：全部回填阴性 + 无 reader。
- **根因保持 PENDING**：resolver 进入 .rdata2 乱码区（0x142c1d6c3→0x1429d6ecc→0x142934069→0x142934089），candidate 读栈垃圾(0x9FD548) vs protected 有效(0x7ff8...)；栈槽差异是 r9 依赖（F6'），非进入前栈分叉。
- **保留**：完整 TLS/resolver 链、两目标都到 0x142934089、v1 .boot 撤销、seal 匹配、ADR7 17/17。

## 四、下一步
1. 追踪 0x142934069 处 r9 来源（Themida 元数据读？）
2. candidate vs protected 的 .rdata2 元数据表在 resolver 入口逐字节 diff
3. 定位后按总指挥批准路径设计

**边界**：冻结修码；GTO-H5-LIVE-AUTHORIZATION-2 不签；≤6 sessions 已用（6 个新 session）。
