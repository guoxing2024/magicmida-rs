# GTO-TR T0-F2 报告：Themida/SecureEngine 公开分析「版本×特征」矩阵与候选引擎排序

**执行**: 子代理（GTO-TR 线 F2）· 模型钉定 deepseek-v4-pro-0813 @ max
**预算**: 11 轮检索（≤20 上限），web_search ×2 / advanced_search(bing) ×7 / platform_search(github) ×2
**样本事实（来自 GTO-TR-0 工单 §2，用于匹配/排除）**:
1. 全节虚拟化 + PE 头加密 + EP 密文
2. TLS 时刻解析器 + unwind 混淆
3. 按页惰性解密（300s 真实运行零新增解密页）
4. 全部厂商字符串被清除
5. 节名含 .KI3 类乱名 + 编号 .data0/.data1 式载荷段

---

## 一、版本×特征矩阵

> 诚实声明：公开的 Themida/SecureEngine 结构级逆向资料非常稀缺。多数命中的是
> 官方宣传页、中文代理商站点、第三方脱壳工具的 README/教程。**版本级的结构差异
> （VM handler 表形态、dispatch 循环特征码、build 间差异）未找到逐 build 的公开权威
> 资料**，以下矩阵基于工具覆盖范围 + 有限公开描述 + 官方版本史常识，凡推断均标注。

| 版本系 | 公开可考结构特征 | 公开工具覆盖 | 与本样本事实匹配 | 冲突 |
|---|---|---|---|---|
| **Themida 1.x** | 早期 SecureEngine；反调试/反 dump 初代；VM 规模小；IAT 基本不全虚拟 | 早期脚本（无维护）；Magicmida 部分兼容 | 弱——1.x 极少用全节虚拟化+按页惰性解密 | EP 密文+全节虚拟化更像 2/3 系 |
| **Themida 2.x（如 2.3.7.0）** | SecureEngine 核心；IAT 可虚拟化可选；TLS 回调反调试成型；反 dump 机制进入成熟期；节名常为自定义名 | **unlicense 官方覆盖**；Magicmida 主力覆盖 | 中——支持 TLS 解析器 + 自定义节名 + 部分虚拟化 | 2.x 的按页惰性解密/全节虚拟化非其显著标签 |
| **WinLicense 2.x** | 与 Themida 同内核，偏商业授权/许可绑定；技术结构接近 | unlicense 覆盖（明确列 2.x） | 中——同内核 | 同 2.x |
| **Themida 3.x（3.1.8.0 / 3.2.5.0）** | **SecureEngine 深化**：更激进虚拟化、VM handler 变体多、执行驱动按页解密、更完善 TLS/unwind 混淆、反 dump 更强 | **unlicense 覆盖 3.x（官方声明）**；另有 bobalkkagi 等实验性 devirtualization | **强匹配**——全节虚拟化+EP 密文+TLS 时刻解析器+unwind 混淆+执行驱动按页解密，全部符合 3.x 宣传特征 | 无直接冲突 |
| **WinLicense 3.x** | 同 Themida 3.x 内核 | unlicense 覆盖 3.x | 强匹配 | 无 |
| **suspected-SecureEngine 变体（未确证）** | 可能是 Oreans 新私有变体或深度自定义 | 无公开工具 | 未知 | 若命中则无现成工具 |

---

## 二、候选引擎排序（按匹配强度）

### 候选 1：Themida 3.x（3.1.x–3.2.x 区间）—— 最匹配 ⭐⭐⭐⭐⭐
- **匹配证据**：① 全节虚拟化 + EP 密文，符合 3.x 深度保护定位；② TLS 时刻解析器 + unwind 混淆，WO-601 行为矩阵与 3.x 已知特征吻合；③ 执行驱动按页惰性解密，与 3.x 深化 SecureEngine 的宣传方向一致；④ 厂商字符串清除是 Oreans 一贯做法（所有版本）。
- **冲突证据**：无硬冲突。节名 .KI3/.data0/.data1 为自定义（Oreans 允许自定义节名，非版本判别强特征）。
- **置信度**：中-高。缺一锤定音的版本 magic byte（公开资料未给出 3.x 特有常量）。
- 相关来源：[Oreans official Themida page](https://www.oreans.com/themida.php) · [百度百科版本表 2.3.7.0/3.2.5.0](https://baike.baidu.com/item/Themida/4588675) · [CSDN Themida 3.1.8.0 深度解析](https://blog.csdn.net/qq_29709589/article/details/147217311)

### 候选 2：WinLicense 3.x —— 并列 ⭐⭐⭐⭐⭐
- **匹配证据**：与 Themida 3.x 同 SecureEngine 内核，技术特征一致；商业授权倾向不影响结构。
- **冲突证据**：无。
- **置信度**：中-高。与候选 1 结构等同，无法仅凭结构区分 Themida vs WinLicense。
- 相关来源：[GitHub unlicense（明确列 WinLicense 3.x）](https://github.com/ergrelet/unlicense)

### 候选 3：Themida/WinLicense 2.x —— 次之 ⭐⭐⭐
- **匹配证据**：TLS 回调反调试 + 自定义节名 + 可选虚拟化，2.x 均具备。
- **冲突证据**：**全节虚拟化 + 按页惰性解密**更偏 3.x 深化特征；2.x 时代按页惰性解密不是显著标签。
- **置信度**：低-中。若 F1 指纹显示 VM 规模偏小/handler 变体少，可回落此档。
- 相关来源：[GitHub unlicense（列 2.x）](https://github.com/ergrelet/unlicense)

### 候选 4：未确证的 SecureEngine 私有变体 —— 保留档 ⭐⭐
- **匹配证据**：若 F1/F2 无法落到已知 build，则保留此档。
- **冲突证据**：无公开对照。
- **置信度**：低。仅作为「指纹对不上所有公开版本」时的兜底。

---

## 三、必答题：有无能直接处理某候选版本的公开工具？

### 结论：有，且不止一个——但它们的范式与 TERMINAL 报告判定的 dump 路线相同，**对本样本大概率无效**（详见 §四）。

| 工具 | 适用版本 | 机制 | 覆盖本样本预期 | 来源 |
|---|---|---|---|---|
| **[unlicense](https://github.com/ergrelet/unlicense)** | Themida/WinLicense **2.x 与 3.x**（动态） | 运行到 OEP 后 dump 内存 + 导入修复（IAT rebuilder） | **❌ 大概率无效**：它本质是「运行→dump→修导入」的动态 unpacker，正是 dump 式路线；本样本按页惰性解密 ⇒ dump 时刻未覆盖页在重建物里仍是密文 ⇒ 独立运行 AV。**最多能验证 OEP/导入层面，但无法产出可运行候选** | [GitHub](https://github.com/ergrelet/unlicense) · [52pojie 讨论](https://www.52pojie.cn/thread-1647083-1-1.html) |
| **[Magicmida](https://github.com/Hendi48/Magicmida)**（本项目前身同名） | Themida 2.x 为主（64/32 位自动脱壳） | 自动 OEP 查找 + dump | ❌ 同上，且覆盖版本更窄（2.x 系） | [GitHub](https://github.com/Hendi48/Magicmida) |
| **[UnpackThemida](https://github.com/TopSoftdeveloper/UnpackThemida)** | Themida/WinLicense 2.x 与 3.x | 动态脱壳 + 导入修复 | ❌ 同上，dump 范式 | [GitHub](https://github.com/TopSoftdeveloper/UnpackThemida) |
| **[bobalkkagi/Themida-3x](https://github.com/bobalkkagi/bobalkkagi)** | Themida 3.x | unpacking + unwrapping + **devirtualization(future)** | ⚠️ **部分相关**：宣称 devirtualization 为「未来」方向，成熟度未知；若实现能解 VM 字节码则跨越 dump 范式，但无公开成熟度证据 | [GitHub](https://github.com/bobalkkagi/bobalkkagi) |

---

## 四、关键分析：为什么「有工具」≠「能完成」

**本样本的致命特征（按页惰性解密）恰好是上述所有动态 unpacker 的已知失效场景。**

unlicense 等工具的范式：让壳运行到 OEP（或观察点）→ dump 此刻内存 → 修复导入。
它假设「到达 OEP 时，壳已解密了全部需要的代码」。

但本样本（TERMINAL 报告实测）：
- 300s 真实运行零新增解密页，覆盖率恒定 4.26%；
- 按页惰性解密 ⇒ 到达任何观察点时的内存快照，只含「当前执行路径」解密过的页；
- 独立重跑走新路径 ⇒ 必踩未解密页 ⇒ AV。

**推论**：unlicense 系列工具对本样本，即便成功跑到 OEP 并 dump，产出的候选镜像
也会在独立运行时空洞百出——这正是仓库 8/22 已经用实测闭合的结论。**工具的「有」
不改变范式的「不可达」。**

唯一跳出 dump 范式的线索是 `bobalkkagi` 的 devirtualization（未成熟），以及
GTO-TR 线自己的 **traced-rebuild（执行历史并集）**——它正面解决「按页惰性」问题，
而这正是本报告支撑立项的地方：**不存在现成工具能做到，所以必须自建。**

---

## 五、覆盖说明

- **已检索**：Themida/WinLicense 版本史与宣传、unlicense/Magicmida/UnpackThemida/bobalkkagi 四工具的覆盖范围、Themida 3.1.8.0/3.2.5.0 中文深度解析、52pojie 社区讨论。
- **未找到（明确标注，不编造）**：
  - 逐 build 的 VM handler 表形态 / dispatch 循环特征码权威资料——**未找到**；
  - Themida 3.x 版本特有的 magic bytes/常量表——**未找到**（正是 F1 应补的结构指纹来源）；
  - 节名 .KI3/.data0/.data1 与特定版本绑定的证据——**未找到**（节名高度可定制，不构成版本判据）；
  - 成熟可用的 SecureEngine 3.x 通用 devirtualizer——**未找到**（bobalkkagi 为实验性「未来」方向）。
- **限制**：所有「版本特征」基于工具覆盖范围 + 有限公开描述 + 常识推断，缺逐 build 二进制级对照；版本判定到「3.x 系」级别可信，到「3.1.x vs 3.2.x」级无公开依据。是否命中私有变体，需 F1 结构指纹（从样本本地提取，非网络可对照）来收口。

**给 Lead 的建议**：F2 的「版本×特征」落到 3.x 系即达信息上限；真正的版本收口依赖 F1 在样本本地提取 handler 表形态去对照社区语料（而非依赖 Web 资料）。且本报告最重要的结论是工具现状：**无现成工具能跨越按页惰性解密范式，traced-rebuild 需自建**。
