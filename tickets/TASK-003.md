# TASK-003 — 堵住 `check_clippy_baseline.ps1` 的软通过

- **优先级**：P0
- **状态**：✅ **完成 R2**（2026-08-29，四条验收由总指挥亲自复跑全过；归档 [runs/20260829-TASK-003-R2.md](../runs/20260829-TASK-003-R2.md)）
- **岗位**：developer
- **预估**：30 分钟

## 项目背景

MagicMida vNext 的 CI 有一个"警告基线"门禁：生产代码里 warn 级 clippy lint 的数量只许降不许升，基线记在仓库根的 `_clippy_baseline`（当前 TOTAL=349），由 `tools/check_clippy_baseline.ps1` 在 CI 的 `windows-clippy` job 里执行。

**这个脚本现在会把编译失败读成"全绿"。** 它拿到 `cargo clippy` 的退出码后只打印一句提示就继续，然后只比较各 lint 的警告计数。
如果 clippy 根本没跑起来（链接失败、语法错误、环境缺失），警告计数全是 0，0 ≤ 基线，脚本打印 `OK: clippy warn baseline holds` 并 exit 0。

本次接管已实测复现：在缺 MSVC 链接环境的 shell 里执行，输出是

```
Running cargo clippy --workspace --lib --bins (JSON)...
NOTE: cargo clippy exited 101 (deny-level lint present).
OK: clippy warn baseline holds (TOTAL baseline=349).
```

一个会把失败读成通过的门，比没有门更危险 —— 它让后面每一次放水都看起来合法。

## 你要改的文件

- `tools/check_clippy_baseline.ps1`（94 行，唯一需要改的文件）

关键位置：第 44-50 行拿 `$LASTEXITCODE` 并注释 `# clippy may exit non-zero on deny-level lints; still parse warnings.`；
第 71-93 行做基线比较并 exit 0。

## 任务目标（一句话可观察的变化）

clippy 因编译/环境原因没能完成分析时，脚本必须**非零退出并说明原因**；只有在 clippy 真正完成了分析（哪怕命中 deny 级 lint）时才继续做基线比较。

## 具体要求

1. **保留**原有的合法场景：clippy 命中 deny 级 lint 时确实会非零退出，这种情况仍要继续解析警告并比基线。所以不能简单地"退出码非 0 就失败"。
2. 区分方式（任选其一或组合，在注释里写清你选了哪个和为什么）：
   - 解析 JSON 输出里有无 `"level":"error"` 且**不是** clippy lint 的诊断（即 rustc 编译错误 / 链接错误）；
   - 统计实际被分析到的 target / crate 数量，为 0 则判定"没跑起来"；
   - 检查 JSON 输出是否为空或行数为 0。
3. 失败时的输出必须能让人一眼看懂是"没跑起来"而不是"警告超标"，例如：
   `FAIL: cargo clippy did not complete analysis (exit=101, 0 targets analyzed) — baseline not evaluated.`
4. 顺手把第 50 行那句会误导人的 `NOTE: ... (deny-level lint present)` 改成不预设原因的措辞。
5. 不要改 `_clippy_baseline` 的数值，不要改 `.github/workflows/ci.yml`。

## 约束

- 只改 `tools/check_clippy_baseline.ps1` 一个文件。
- 不得引入新依赖（PowerShell 内置能力足够）。
- 不得降低基线数值来让门禁变松。
- 不得提交、不得推送。

## 本机环境（必读）

Git Bash 的 `PATH` 会把 `link.exe` 解析到 Git 的 GNU coreutils，clippy/cargo 链接必失败 —— **这正好是你要用的"负面测试环境"**。
需要正常环境时用 `tools/_enter_msvc_env.cmd`：

```bash
cd "D:/Claude project/magicmida-rs"
printf '@echo off\ncall tools\\_enter_msvc_env.cmd || exit /b 1\npowershell -NoProfile -ExecutionPolicy Bypass -File tools/check_clippy_baseline.ps1\necho EXIT=%%ERRORLEVEL%%\n' > _run.cmd
sed -i 's/$/\r/' _run.cmd && cmd //c _run.cmd; rm -f _run.cmd
```

跑完删掉你自己造的临时脚本，逐个按名字删，不要用通配符。

## 验收标准（两条命令判生死）

1. **负面用例（没跑起来必须失败）**：在**没有** MSVC 环境的 Git Bash 里直接执行
   `powershell -NoProfile -ExecutionPolicy Bypass -File tools/check_clippy_baseline.ps1; echo "EXIT=$?"`
   → **退出码非 0**，且输出里明确说明是"clippy 未完成分析"，不是"基线超标"。
2. **正面用例（正常环境必须通过）**：在 `tools/_enter_msvc_env.cmd` 环境下执行同一脚本
   → **退出码 0**，输出 `OK: clippy warn baseline holds (TOTAL baseline=349)`。
3. 回归：`cargo fmt --all -- --check` 不受影响（本工单不碰 Rust 代码，此条只是确认你没误改别的文件）。

## 交付格式

写到 `runs/20260829-TASK-003.md`，必须粘贴上面**两条命令各自的完整原始输出**（含退出码）——
这个工单的全部价值就在于"两种环境下行为不同"，只贴一条等于没验证，直接打回。
最后必须有「我不确定的事」一节。

## 停止规则

同一条验收标准连续 2 次不通过就停下来报告。
如果你发现无法在不误伤"deny 级 lint 命中"这个合法场景的前提下区分两者，**停下来把你的分析写出来**，不要用"退出码非 0 就失败"这种会误伤的粗暴方案糊过去。

---

## 第 1 轮打回（2026-08-29，验收人：总指挥）

第 1 轮交付被**打回**，完整记录在 `runs/20260829-TASK-003-REJECT-1.md`。返工者读下面即可，两处内容冲突时以本节为准。

### 打回理由

1. **致命：E 前缀 rustc 编译错误被放行。** 验收人亲自在 `crates/cli/src/main.rs` 注入 `let probe: u32 = "deliberate type error";`（E0308），MSVC 环境下运行脚本，输出 `NOTE: cargo clippy exited 101 (deny-level lint present).` + `OK: clippy warn baseline holds` + **exit 0**。真正的编译错误被判成基线通过。原因：分类器以「有无 lint code」区分，但 rustc 编译错误带 `E` 前缀 code（E0308/E0277/E0432…），`$msg.code.code` 非空，全被计入 deny 命中桶放行。工单「具体要求」第 2 条明文要求识别 "rustc 编译错误 / 链接错误"，只覆盖链接错误不算覆盖。
2. **违规：具体要求第 4 条未执行。** `NOTE: ... (deny-level lint present)` 那句原文未改，在编译错误场景原形毕露。

### 返工要求

- 只改 `tools/check_clippy_baseline.ps1`；`runs/20260829-TASK-003.md` 覆盖重写（含第 2 轮全部验收输出，保留第 1 轮已验证结论也可）。
- 修正分类器，建议按 code 前缀三分：无 code → 编译/链接失败；`clippy::` 前缀 → deny 命中（合法放行）；其他（`E` 前缀、rustc lint 名如 `unused_variables`）→ 编译失败。**注意**：rustc 自身 lint（deny 级，如 `unused_variables`）code 无前缀，如何归类要在注释里写清理由。
- 第 4 条一并补：改成不预设原因的措辞（例如 `NOTE: cargo clippy exited non-zero, analyzing whether analysis completed...`）。

### 第 2 轮验收标准（四条全过才收）

1. **负面（链接失败）**：Git Bash 直接跑 → exit 非 0，说明是"未完成分析"。
2. **负面（编译错误 E 前缀）**：临时在 `crates/cli/src/main.rs` 注入一行类型错误（如 `let probe: u32 = "x";`），MSVC 环境跑 → **exit 非 0**；跑完恢复原文件，`git diff --stat` 证明无残留并粘进报告。
3. **正面（OK 路径）**：健康树 + 镜像基线（把 `_clippy_baseline` 复制到临时文件，按实际计数上调 5 项、补 3 条新 lint，TOTAL=359）→ `OK: ... holds` + exit 0。跑完删临时基线。
4. **正面（deny 命中不误杀）**：`CARGO_CLIPPY_EXTRA_ARGS="-- -D clippy::let_unit_value"` 环境变量注入 → 脚本继续做基线比较，**不得**报"未完成分析"。

注意本机 Git Bash 无法链接（E-1），第 2/3/4 条都在 `tools/_enter_msvc_env.cmd` 环境下跑；临时 `.cmd` 必须 CRLF。镜像基线数据点（2026-08-29 实测）：unnecessary_cast 18、manual_saturating_arithmetic 16、let_unit_value 4、type_complexity 8、unnecessary_map_or 14，新 lint 三条 inconsistent_digit_grouping=1 / unused_unsafe=1 / unused_variables=1，TOTAL=359。
