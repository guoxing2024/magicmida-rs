# 授权书 XC-XXI — core.dll 完美路径判定实验

> 状态：✅ **已授权（owner 签署 2026-08-29）**　申请人：worker-I / 小助手（总指挥起草）
> 本文件原为申请模板；**owner 已确认"授权范围无误，签署。账本 XC-XXI 按 0/4 起"**，即刻生效开账。
> 空白模板保留于本文件 §模板存档（供后续战役复用）。

---

## 〇、申请依据与背景

- **样品**：`core.dll`（`D:\Tools\RE\dumps\xiongxiong\core.dll`，sha256 `09f3dd34…`，6,038,032 B），case_id `xiongxiong_core`
- **现状**（已核实，全部落盘 vault）：
  - XX-III 账本 **4/4 COMPLETE**（GVM-0 复检终态 4/8，第 5 格收回）——已收账；
  - 候选 `core_candidate_nep.dll` 达 **equivalence-grade**：真实宿主加载成功、基址精确命中、解密 .text 保持、GetAppVersion 行为可用（`xx3_attempt_4/s4_host_integration.json`）；
  - **S4 = PARTIAL**：完整业务调用链未验证（宿主 EXE 壳态）；
  - **剥壳节路径已判死**：应用逻辑 VM 化于 `.winlice`（`CORE_INDEPENDENT_CHARACTERIZATION.md` §4）；
  - 宿主熊熊 rev2 EXE **已完美脱壳**（xx11 收官，`rev2_unpacked.exe`）。
- **依据文档**：`AUTHORIZATION_XX_20260827.md`（含 XC 追加节）、`CORE_INDEPENDENT_CHARACTERIZATION.md`、`docs/GVM-0_RULING_20260828.md`、`docs/TASK_BOARD_20260829.md` T0.3。

## 一、申请范围（本次授权解禁项）

针对 vault 锚定样品 `xiongxiong_core`，**解禁**以下动作（一次性判定实验，非主工程承诺）：

1. **VM 机制判定**：宿主进程加载候选 core.dll，调用 `GetAppVersion`/`Run`，页级监控判定 `.winlice` VM 逻辑为
   **「运行时解密实体化」** 或 **「纯解释执行」**；
2. **S4 宿主补测**：以已脱壳 `rev2_unpacked.exe` 为宿主，LoadLibrary 候选 core.dll，验证完整业务调用链
   （GetAppVersion/Run 真实调用 + config 语义），产出 S4 verdict（full / partial / fail）；
3. **明文产物捕获**（**条件触发**，仅当判定为实体化型）：验证 XC-3-A 模块感知 dump 能否捕获完整解密产物；
   不足时允许最小改造 `dump.rs`（模块级，不改证据/验收路径）；
4. **不包含**：对 `.winlice` 的剥离、VM 语义逆向、lifter/devirt 研制（属 GVM 战役范围，本单不涉）。

## 二、账本与门禁

- **账本**：`XC-XXI`，建议 0/4 起步，每格一次实弹 attempt；owner 门禁放行。
- **判定门（go/no-go）**：
  - 门 1（VM 机制判定）：产出页级证据，明确实体化型 or 解释型；
  - 门 2（S4 补测）：完整业务调用链 verdict；
  - 若实体化型 → 转入完美候选产出；若解释型 → **B1 判死，回退依赖 GVM devirt**，账目封存。
- **周期**：判定实验一次性（1-2 格），不追溯已耗投入。

## 三、红线（不变，沿 AUTHORIZATION-XX / GVM-0）

- 禁止样品/重建产物/保护器知识向第三方分发或部署；
- 禁止对非 vault 锚定目标使用本线方法；
- 禁止绕过验收核伪造证据；
- 无干扰模式（NO_BYPASS=1）全程；vault mismatch 即 STOP；
- 所有新证据入金库（`D:/MidaVault/lab/evidence/xiongxiong_core/`，内容寻址）。

## 四、预期交付

| 交付 | 验收 |
|---|---|
| 判定实验报告（VM 机制 + 页级证据） | 明确实体化/解释结论 |
| S4 补测结果 | full / partial / fail + reason |
| （条件）完美候选 + S1-S4 证据 | 结构/明文/存活/行为全过，对照熊熊标准 |

## 五、签署

- **申请人（worker-I）**：__worker-I（申请发起）__
- **总指挥审核（小助手）**：__已审核，授权范围与账本无异议，2026-08-29__
- **owner 签署**：__✓ 授权（chat 确认，"授权范围无误，签署。账本 XC-XXI 按 0/4 起"），2026-08-29__
- 签署后本单即刻开账；收口或目标达成时出具判定报告。

---

## 六、签署生效记录

- **签署时间**：2026-08-29 01:58 (GMT+8)
- **账本**：XC-XXI 0/4 起步
- **生效范围**：§一 申请范围第 1-4 项（VM 机制判定 / S4 宿主补测 / 条件 dump 捕获 / 明确不含 .winlice 剥离与 devirt 研制）
- **后续动作**：T0.3 状态 → 🔧 执行中；worker-I 开账执行，产出经总指挥审核后回报 owner。

## 七、追加授权（owner 2026-08-29 02:32，"两个都授权"）

在判定实验完成（路径 A 确认）基础上，**追加授权**：

1. **Run 业务链补测豁免**：允许在**隔离实验环境**触发候选 core.dll 的 `Run` 导出（含 urlmon.URLDownloadToFileA 调用点）。**网络红线维持不变**（manifest `network.mode=deny_all` 保持）：Run 触发时下载应被环境拒绝/记录，观察业务链执行路径至调用点即视为行为证据；不得在非隔离环境触发。
2. **完美候选产出化**：开工作单 **XC-XXI-B**（账本 0/4 起），目标基于判定结论（路径 A：运行时解密实体化）产出 **S1-S4 达标候选**（对照熊熊标准），含 Run 补测、明文产物固化、结构/存活/行为全量验证。

**生效范围**：本追加授权覆盖 §一 范围不足处，红线（NO_BYPASS=1 / vault STOP / 不外发 / 禁伪造证据 / 网络 deny_all）全部延续。
**签署**：owner ✓（chat 确认"两个都授权"），2026-08-29 02:32；总指挥已登记。

---

*模板依据：GVM-0 裁决书格式（owner 签署 + 尽职核查 + 授权范围 + 红线 + 账本门禁）。空白模板可复用：将本文 §一~§四 复制为新申请书，签署栏留空。*
