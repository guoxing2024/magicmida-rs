# MagicMida vNext Agent-Teams 安全审计报告

- **审计对象**: `magicmida-rs`（Windows PE 脱壳研究平台，Rust workspace，~248 个 `.rs` 文件 / 约 20 万行，GPL-3.0）
- **审计方式**: Agent Teams 编排 —— Team Lead 协调 + 6 名专项审计员并行审查 + Lead 对高危发现逐条交叉验证
- **审计性质**: 纯静态审查（未构建、未运行、未修改任何文件）；所有发现均有 `文件:行号` 证据
- **团队编制**:
  | 代号 | 专项 | 结果 |
  |---|---|---|
  | A | 内存安全 / unsafe 纪律 | ✅ 交付 |
  | B | PE 解析健壮性（不可信输入） | ✅ 交付 |
  | C | 进程操作面 / 文件路径安全 | ✅ 交付 |
  | D | fail-closed 声明验证 | ✅ 交付（1 条高危被 Lead 复核推翻） |
  | E | 供应链 / 构建链 / CI | ✅ 交付 |
  | F | 仓库卫生 / 信息泄露 | ✅ 交付 |

---

## 一、总体结论

代码库整体工程质量**显著高于同类逆向工具的平均水准**：

- 解析层系统性使用 `checked_add`/`get()`/循环硬上限，未发现可由畸形 PE 直接触发的远程越界或 panic；
- 进程创建无命令行拼接注入面，env 门控统一 `== Some("1")` 字面比较、默认方向全部 fail-closed；
- 样本快照的 TOCTOU 处理（双读双哈希 + 三次磁盘重读 + 内容寻址存储）属教科书级；
- 五条 fail-closed 文档声明中四条经实现验证成立；
- **未发现任何真实凭证泄露**（无 token/API key/私钥）。

主要问题集中在四处：**① v1 FFI 入口对调用方指针契约的盲目信任**（与其自家 V2 路径的严谨形成鲜明反差）；**② 文件写边界的残留竞争模式**（固定临时名 + 非 `create_new` 写入 + 别名校验单点化）；**③ CI 第三方 action 全部浮动 tag 未 pin SHA 且无 permissions 块**；**④ 公开仓库跟踪文件中内嵌本机用户名与机器路径**（违反其自定 ARTIFACT_POLICY）。

**综合风险评级：中低。** 无可直接远程利用的高危漏洞；最严重的问题是本地信任边界内的 FFI 契约缺陷与供应链卫生。

---

## 二、确认发现（按严重度排序，均经 Lead 复核）

### H-1 [高][已确认] v1 FFI 入口无界原始指针数组解引用（信任边界缺陷）
- **位置**: `crates/antidebug-runtime/src/exports.rs:247-252`
- **描述**: `MidaAntidebugInitialize`（v1 入口）中 `for i in 0..p.expected_hooks { let sp = unsafe { *p.expected_surfaces.add(i) }; ... }` 对 `*const *const c_char` 数组逐项解引用。`expected_hooks` 为 64 位 usize，仅检查 `> 0` 无上界；数组长度完全依赖注释中的 "caller contract"。随后每个指针又进入 `read_cstr` 做无界扫描。该代码运行在**目标进程内部**——若控制器传入的参数 blob 被篡改或构造错误，即在目标进程内任意 OOB 读。
- **对比**: 同文件 V2 路径（L591-780）对同一数据做 blob 内自相对偏移 + `[blob_base, blob_end)` provenance 校验 + checked_add 链——项目自己已经证明知道正确做法。
- **触发条件**: v1 入口收到越界 `expected_hooks` 或损坏指针数组。
- **修复**: v1 路径对齐 V2 的校验标准；给 `expected_hooks` 加硬上界。
- **CWE-125 / CWE-119**

### M-1 [中][已确认] CI 第三方 action 浮动 tag 未 pin SHA，且 job 无 permissions 块
- **位置**: `.github/workflows/ci.yml:17,20,64`（checkout@v4 / dtolnay rust-toolchain@stable / embarkstudios cargo-deny-action@v2）
- **描述**: 三个 action 均引用可移动 tag；任一上游仓库被攻陷或 tag 重指即向 CI 运行器注入任意代码。缓解因素：仅 `pull_request`/`push` 触发、workflow 未暴露 secrets、matrix 命令为静态字符串（无表达式注入）。
- **修复**: 全部 pin 到完整 commit SHA；各 job 增加 `permissions: contents: read`。
- **CWE-1357**

### M-2 [中][已确认] antidebug 证据写入用固定临时名 + 非原子 `fs::write`（可抢占 + 残留）
- **位置**: `crates/cli/src/unpacker/antidebug_controller.rs:1628-1632, 1646-1649`
- **描述**: `write_walker_evidence` / `write_failure_evidence` 用固定文件名 `mida_antidebug_walker.evidence.json.tmp` 执行普通 `std::fs::write` 再 rename。同目录预置同名 symlink/junction 可致任意文件覆盖（写跟随链接）；进程在 rename 前被杀则残留敏感证据。同仓库 `sidecar_io::atomic_write` 已有正确实现（`create_new` 唯一临时名 + fsync + MoveFileExW），此处属标准落差。
- **修复**: 两处统一改用 `sidecar_io::atomic_write`。
- **CWE-377 / CWE-378 / CWE-459**

### M-3 [中][已确认] 输出路径别名保护仅在解析时单点执行，且不规范化 `..`/ADS；写入前无重校验
- **位置**: `crates/cli/src/unpacker/helpers.rs:64-77` + `unpacker/mod.rs:749-752`（post_loop 写入点 `post_loop.rs:403`）
- **描述**: `-o/--output` 只在与**输入**做一次别名比较（该比较本身质量很高：canonicalize + 大小写不敏感 + 卷/文件索引）；之后穿越整个调试循环才最终写入。窗口内目标位置可被换成 symlink/junction 使实际落点改变；且对 `..\` 上跳、绝对路径覆盖、NTFS ADS 冒号路径无拒绝逻辑。README 声称 "Report paths must not overwrite the candidate or oracle"，主输出路径的保护强度低于该声明。另 `/dump-process <pid> <file>`（`args.rs:430` → `dump.rs:54`）完全无任何防护。
- **修复**: 在写入点复用文件身份校验重跑一次；对 `..`/ADS/驱动器根 fail-closed。
- **CWE-367 / CWE-59 / CWE-22**

### M-4 [中][已确认] `read_cstr` 越界 +1 读（4096 字节窗口外）
- **位置**: `crates/antidebug-runtime/src/exports.rs:1603-1606`
- **描述**: `while unsafe { *p.add(len) } != 0 && len < 4096 { len += 1 }` 先解引用后判界——字符串恰好在窗口边界无 NUL 时会对第 4096 字节（窗外 1 字节）执行读取后才退出。函数无缓冲区长度参数。
- **修复**: 改为先判界再读（`if len >= 4096 { return None }`）或传入缓冲区上限。
- **CWE-125**

### M-5 [中][已确认] thunk 代码页最终态为 PAGE_EXECUTE_READWRITE（W^X 破坏）
- **位置**: `crates/cli/src/unpacker/runtime_loader.rs:1355-1363`（代码与参数内嵌同一 0x100 页）
- **描述**: 远程 thunk 页写入后直接置为 RWX 并 CreateRemoteThread。目标进程内其他线程/注入体覆写该页即可劫持执行。属防御纵深缺失。
- **修复**: 调用前切 `PAGE_EXECUTE_READ`；code 与 args 拆分到不同保护属性的页。
- **CWE-732**

### M-6 [中][部分待核实] PE 解析关键路径依赖小众低下载量 crate 生态
- **位置**: `Cargo.lock:55-67,264-300`（pelite 0.10 → dataview 1.0.2 → derive_pod 0.1.2；no-std-compat 0.4.1；pelite-macros）
- **描述**: pelite/m4b 生态 crate 维护者单一、审查面窄，却处于解析不可信 PE 输入的关键路径（dataview 做 Pod 类型重解释）。zmij 为 serde_json 传递依赖（dtolnay 出品，信任度高）；winapi 旧代随 pelite 引入（已停维护）。注：是否真实存在可利用缺陷未经动态验证，标"待核实"。
- **修复**: 保持 Cargo.lock 锁定 + cargo-deny advisories 常态化；评估 pelite 升级路线。
- **CWE-1357**

### M-7 [中][已确认] 公开仓库跟踪文件内嵌本机身份与环境信息（违反自家 ARTIFACT_POLICY）
- **位置（抽样）**: `evidence_staging/R5_R3_baseline_cargo_test.txt:140+`（原始 link.exe 命令行含 `C:\Users\Administrator\.cargo\...` 与工作区绝对路径）、`WORKER_HANDOFF.md:72-80`（外部金库路径 `D:\MidaVault\lab\evidence\...` + 完整样本 SHA-256）、`HANDOFF_PROMPT_H6_LIVE1.md:3`、`docs/AUDIT_BATCH15_20260823.md:51` 等
- **描述**: 8 个 cargo 输出 txt（106–236KB）+ 多份运维交接文档被 git 跟踪，泄露本机用户名 `Administrator`、机器路径、金库布局。ARTIFACT_POLICY.md 第 16 行明确要求清单不含机器特定绝对路径——政策与现状矛盾。缓解：未发现任何真实凭证；`*.log` 类高风险文件已被 .gitignore 正确拦截未入库；git 历史删除记录干净。
- **修复**: 移出跟踪并外置金库；`.gitignore` 增补 `evidence_staging/**/*.txt`；文档中机器路径改占位符。（公开仓库历史中已存在的泄露需考虑改写历史或视为已公开。）

### L 组（低危，摘要）
| 编号 | 发现 | 位置 | 说明 |
|---|---|---|---|
| L-1 | `WriteProcessMemory(..., None)` 不校验部分写入 | runtime_loader.rs:1663-1671 等 3 处 | 下游 V2 解析器 fail-closed 兜底，后果钳制为拒绝；建议传 `Some(&mut written)` 校验 |
| L-2 | `usize`→函数指针 `transmute` | runtime_loader.rs:927-930,1077 | 严格 provenance 下 UB 隐患；CreateRemoteThread 本就收 `*const c_void`，可免转 |
| L-3 | thunk 拷贝长度仅 `debug_assert` 保护 | runtime_loader.rs:1325-1326 | release 下超长会 panic 穿透 FFI 边界；改为显式 Err |
| L-4 | `MIDA_B4_TIMELINE` env 决定任意写路径 | unpacker/mod.rs:1371-1373 | 收敛到受控输出目录下 |
| L-5 | msvc_crt u32 截断仅在 >4GB 节可达越界 panic | packers/themida/src/oep/msvc_crt.rs:158,190-191 | `usize::try_from` 替代 `as u32` |
| L-6 | acceptance `same_file` 在非 unix/windows 平台恒返回不相等 | crates/acceptance/src/main.rs:1283-1291 | 主流平台不受影响；fallback 应改 Err（fail-closed） |
| L-7 | manifest 校验遗留路径正则可被非边界词嵌入绕过 | lab/cases/verify_manifests.py:16-19,59-65 | `dirruntime_triage` 类拼接漏网；哈希正确性由内容重算兜底（强），格式校验建议显式 hex64 |
| L-8 | PS1 wrapper `LASTEXITCODE` 为 $null 时默认 exit 0 | tools/resolve_gto_source_revision.ps1:124-125 | 极端场景失败伪装成功；null 应映射非零 |
| L-9 | `Verdict::Accepted` 变体存在且 exit_code()=0 | crates/acceptance/src/verdict.rs:28-31 | 靠双层硬停维持"永不输出"；建议类型级排除 |
| L-10 | .bat 硬编码 vcvars64 绝对路径；t_b2.bat 编码损坏 | build_with_msvc.bat:9 / t_b2.bat:2 | 改 vswhere 定位；UTF-8 BOM 重存 |
| L-11 | 陈旧 `exclude = ["crates/bwhook"]`（目录已不存在） | Cargo.toml:16 | 删除或注释说明 |
| I-1 | `Disassembler::new` 对非法 bitness assert panic | crates/disasm/src/decoder.rs:22 | 当前调用链不可达；建议返回 Result |

---

## 三、fail-closed 声明验证裁决

| # | 声明 | 裁决 | 关键证据 |
|---|---|---|---|
| a | GTO mutable locator 必须哈希匹配，不匹配即 SampleIdentityMismatch 终止 | ✅ **成立** | resolver 全错误分支非零退出、无吞错 exit 0；sha 全链路小写字符串比较无解码歧义（_resolve_gto_source_revision.py:158-175,297-302） |
| b | 快照 capture 后/seal 前/启动前反复 re-verify，tamper 永不产出 envelope | ✅ **成立** | capture 双读双哈希（sample_snapshot.rs:590-790）+ staging 磁盘重读（1007-1039）+ pre-seal/pre-launch 两道边界（commands.rs:350-352,198-200）；输入必须位于 snapshot_root 下（commands.rs:413-419） |
| c | R0B 永不 Accepted；report 不覆盖 candidate/oracle | ✅ **成立**（附缺口 L-6/L-9） | 库层强制降级（check.rs:64-72）+ CLI 层 exit 1（main.rs:679-683）双保险；report 防覆盖基于 volume serial + file index 而非路径字符串（main.rs:1216-1281） |
| d | 默认构建识别 GTO 未 opt-in 时 fail-closed | ✅ **成立** —— **队员 D 的高危判定经 Lead 复核推翻** | 路由层（plugin_host.rs:188-194）确无 opt-in 门，但重能力有三道独立 fail-closed 门：feature 硬门（plugin_host.rs:103-121 "GTO route disabled in default build"）、profile 门（mod.rs:282-326）、cfg 门（post_attach.rs:414-437）。默认构建下仅共享观察循环运行——这正是 README 文档化的 G1 共享骨架设计 |
| e | manifest 校验器拒绝遗留路径引用 | ⚠️ **部分成立** | drive/绝对/`runtime_triage`/`cases` 令牌被拦，但存在 L-7 边界词绕过；哈希完整性由内容重算强兜底 |

---

## 四、正面观察（值得保持的实践）

1. **windows_debugger.rs 句柄纪律极佳**：全部 Win32 句柄 RAII 包裹、所有返回路径 CloseHandle 平衡、DEBUG_EVENT union 按 dwDebugEventCode 精确配对访问。
2. **V2 参数 blob 是全面的反面防线**：checked_add 链 + blob 内 provenance 校验 + 有界 slice 解析，配大量 wire 溢出负向测试。
3. **PE 解析上限体系完备**：节表 256 / 导入描述符 100 / thunk 500-100 万 + seen_slots 去重 / TLS 回调槽上限——分配炸弹与无界循环被系统性阻断。
4. **样本快照 TOCTOU 处理一流**：内容寻址 + create_new + TempGuard RAII + no-replace 发布。
5. **deny.toml 治理到位**：yanked=deny、多版本 deny、sources 白名单、openssl-sys 显式禁用——强于多数同类个人仓库。
6. **工具脚本干净**：tools/*.ps1|py 无 iex/DownloadString/shell=True 命中；subprocess 仅调自有二进制。
7. **env 门控哲学统一**：精确 `"1"` 字面比较，杜绝任意非空解锁。
8. **无凭证泄露**：全仓扫描零真实 secret；提交者使用 GitHub noreply 邮箱。

## 五、修复优先级

- **P0（本周）**: M-1 pin CI actions SHA + permissions；M-7 清理跟踪的日志/证据文件与机器路径泄露
- **P1（近期）**: H-1 v1 FFI 对齐 V2 校验；M-2 统一 atomic_write；M-3 写入点重校验 + ADS/上跳拒绝；M-4 read_cstr 判界顺序
- **P2（计划）**: M-5 W^X；L-1~L-5；L-7 正则收紧；L-8 exit code 加固
- **P3（卫生）**: L-6/L-9/L-10/L-11；WORK_ORDERS 归档至 archive/

## 六、覆盖与限制

- **已深读**: core/windows_debugger.rs、antidebug-runtime/exports.rs、cli 的 args/commands/run_spec/helpers/sidecar/sample_snapshot(定点)/runner_preflight(定点)/runtime_loader(定点)、pe 的 header/export_table/tls/relocation/original_imports/dump_process(定点)、disasm 全部、acceptance 的 main/check/verdict、tools resolver 双脚本、verify_manifests.py、ci.yml、deny.toml、Cargo.lock、三个 .bat。
- **未深读**（后续审计建议优先）: pe/src/dumper/raw_slab_coherence.rs（903KB，仅 grep）、rebuild.rs/exception_table 深度核验、packers/themida 其余模块、heap_global_snapshot.rs、unpacker 其余 30 文件的 unsafe 区段、case-manifest.schema.json 的 hash pattern。
- **限制**: 纯静态分析，未构建/未运行/无动态验证；依赖下载量与上游活跃度未联网核实（标注"待核实"项）；所有结论基于调用点契约与周边上下文推演。
