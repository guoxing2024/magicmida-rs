# P8.1.1-A —— 真实 P7-R2 taxonomy 重放

**状态:** 完成
**范围:** 纯离线只读。仅显式只读读取 P7-R2 `bundle_gate_report.json`；不写 P7-R2 execution root；未访问 Vault 其他内容；未启动任何真实样品；未执行 P9。

## 输入

```
D:/MidaVault/scratch/p7_r2_live_smoke_c8258b3_20260805_205032/report/bundle_gate_report.json
```

- **输入 SHA-256（分类前后均验证）**：`29b7dfb93034989fb32bae88833670ff6fe8304804d90482e0c08768e9568b40`
- 大小：4,153,407 字节（分类前后一致）
- 分类后复算 SHA-256 与基线完全匹配 → **输入字节未变化**。

该报告是 `mida.oreans-two-sample-bundle-gate/v1`（bundle-gate report），其 v8 gate 样本位于 `gate.samples` 下。`mida-acceptance classify-gate-report` 已扩展为同时接受顶层 `samples`（raw two-sample-gate）与 `gate.samples`（bundle-gate）两种形状。

## 实际执行命令

```
mida-acceptance classify-gate-report \
  D:/MidaVault/scratch/p7_r2_live_smoke_c8258b3_20260805_205032/report/bundle_gate_report.json \
  --report D:/Temp/p7r2_classify.json
```

- **exit code**：`0`
- 分类输出写入 `D:/Temp/p7r2_classify.json`（scratch，非 P7-R2 root），并打印到 stdout。

## 逐 case taxonomy 计数

### origin_macro（total_failures = **337**）

| bucket | count |
|---|---|
| prerequisite/survival/structural | 4 |
| oep | 9 |
| iat-final-import-mapping | 298 |
| iat-unresolved | 0 |
| relocation | 4 |
| section-rebuild | 18 |
| behavior | 3 |
| isolated-replay | 1 |
| **other** | **0** |
| **unclassified** | **0** |

### lunlun_software（total_failures = **1504**）

| bucket | count |
|---|---|
| prerequisite/survival/structural | 4 |
| oep | 9 |
| iat-final-import-mapping | 43 |
| iat-unresolved | 1423 |
| relocation | 4 |
| section-rebuild | 17 |
| behavior | 3 |
| isolated-replay | 1 |
| **other** | **0** |
| **unclassified** | **0** |

## 验证结论

- `origin_macro total_failures = 337` ✅
- `lunlun_software total_failures = 1504` ✅
- 两个 case 的 `Other = 0`、`unclassified = 0` ✅
- 已知语义计数（P8-A `docs/P8_A_FAILURE_TAXONOMY.md` 记录的 P7-R2 分类结果）**全部核对一致**：
  - origin：4/9/298/4/18/3/1 ✅
  - lunlun：4/9/1423/43/4/17/3/1 ✅

无一计数漂移、无 Other、无 schema 不兼容。**未修改 P7 报告、未修改分类器去迎合预期文本**（分类器只在读入 bundle-gate 顶层形状时做了 schema 兼容，分类逻辑未改）。

## 合规

- 不在 P7-R2 execution root 内写任何文件（分类命令只读输入，输出到 scratch/stdout）。
- 默认测试不访问 D:/MidaVault；本次仅显式只读读取指定的 P7-R2 报告。
- 未执行 P9、未启动真实样品、未声明 live/perfect/universal/10/10/final acceptance。
