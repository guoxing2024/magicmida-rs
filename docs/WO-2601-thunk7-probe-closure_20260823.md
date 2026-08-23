# WO-2601 交付 — thunk7 probe runtime layout + exact-byte closure

**审计基线**：`9589fd13f8e45e7612b212335bcae4c0b1ede23e`（`9589fd1`，Batch 29 最终 HEAD；历史绑定链：639eee3（原始交付）→ 928047f（WO-2701）→ dea085b（WO-2802）→ 9589fd1（WO-2902））
**性质**：local x64 runtime + design fixture；不实现生产 thunk；不运行远程

## 1. 修复的缺陷（Batch 25 审计）

| 缺陷 | 修复 |
|------|------|
| Args10 无 reserved 字段 → rsp_probe 实际在 +0x40，探针写 +0x48，读零值假阳性 | 布局改为 ThunkArgs7Probe（reserved +0x40、rsp_probe +0x48、sizeof 0x50）+ `_Static_assert` |
| 无真实写入证明（清零字段低 4 位通过） | 非零 sentinel `0xDEADBEEFCAFEBABE`，探针必须覆盖它 |
| "65B"叙述错误 | 修正为 production 60B / test 64B |
| production call@0x35 与 test call@0x39 未分离 | 分离并逐字节验证 |

## 2. 布局（冻结，与 WO-2501-thunk7-runtime-contract.h 一致）

~~~c
typedef struct ThunkArgs7Probe {
    uint64_t fn_ptr;     /* +0x00 */
    uint64_t arg0;       /* +0x08 */
    uint64_t arg1;       /* +0x10 */
    uint64_t arg2;       /* +0x18 */
    uint64_t arg3;       /* +0x20 */
    uint64_t arg4;       /* +0x28 */
    uint64_t arg5;       /* +0x30 */
    uint64_t arg6;       /* +0x38 */
    uint64_t reserved;   /* +0x40 */
    uint64_t rsp_probe;  /* +0x48 (written by 49 89 63 48) */
} ThunkArgs7Probe;         /* 0x50 */
_Static_assert(sizeof(ThunkArgs7Probe) == 0x50);
_Static_assert(offsetof(ThunkArgs7Probe, reserved) == 0x40);
_Static_assert(offsetof(ThunkArgs7Probe, rsp_probe) == 0x48);
~~~

## 3. Production 60B vs Test 64B（分离，冻结）

### 3.1 production THUNK7_CODE（60B，call rax @0x35）

字节（与 WO-2301-thunk7-fixture.h THUNK7_CODE 逐字节一致）：

~~~text
49 89 CB 49 8B 03 49 8B 4B 08 49 8B 53 10 4D 8B 43 18 4D 8B 4B 20
48 83 EC 38 4D 8B 53 28 4C 89 54 24 20 4D 8B 53 30 4C 89 54 24 28
4D 8B 53 38 4C 89 54 24 30 FF D0 48 83 C4 38 C3
~~~

- call rax (FF D0) 位于 **0x35**
- SHA-256：`9B6F4A7A138B3C4C5523CEDD047745C96AA83CA01614BEB703E4994DA2E1F017`
- 验证：fixture 数组提取 SHA == obj .text$mn 非连续 production slices 提取 SHA（obj[0x00..0x35) || obj[0x39..0x40)，非连续切片，不是前 60B 连续字节）== 上述值（三者一致）

### 3.2 test extension（64B，probe @0x35-0x38，call rax @0x39）

在 production 的 0x35 处插入 4B probe（`49 89 63 48` = mov [r11+0x48], rsp）：

~~~text
... 4C 89 54 24 30 49 89 63 48 FF D0 48 83 C4 38 C3
                    ^probe@0x35  ^call@0x39
~~~

- SHA-256（test 64B）：`01DC2017D8825EFD7E1C3FBE186C2FACF36FB22F2338C493C422E659476E17AE`
- 测试版仅用于本机 ABI harness；**生产 thunk 禁止包含 probe**

## 4. 三项独立检查结果（LOCAL x64，非远程）

源：D:\Temp\thunk7_final_test.c（C_HASH `1196A360...`）+ thunk7_final_full.asm（ASM_HASH `94552912...`）
输出：D:\Temp\thunk7_threecheck_stdout.txt（OUT_HASH `5D84C68F...`）

~~~text
ok   arg pass-through: all 7 intact
ok   callee entry rsp mod 16 = 8
ok   call pre-rsp mod 16 = 0 (probe wrote 000000d758d7f6a0)
ok   reserved +0x40 intact
THUNK7 THREE-CHECK PASS
EXIT=0
~~~

| 检查 | 方法 | 结果 |
|------|------|------|
| 1. arg pass-through | callee asm stub 写 slot[0..6]，比对 7 值 | PASS |
| 2. callee entry alignment | asm stub 入口**首指令**记录 rsp mod 16（无 prologue 干扰） | PASS（=8） |
| 3. call-pre-rsp | probe 写 +0x48；**sentinel 0xDEADBEEFCAFEBABE 被真实覆盖**（probe wrote 真实 rsp 值），mod 16 == 0 | PASS（=0） |
| 附加. reserved 完整性 | +0x40 未被探针触碰（值保持 0xA5A5...） | PASS |

**sentinel 证明**：rsp_probe 预置 0xDEADBEEFCAFEBABE；探针执行后该值变为真实 rsp
（如 0x000000d758d7f6a0）——证明 `49 89 63 48` 确实写入了 +0x48，非零值读取
（非清零假阳性）。

## 5. obj 字节证明（exact-byte 提取，WO-2701 修正）

- 被测对象：thunk7_final_full.obj（OBJ_HASH 9D76E5E0D0A66924987DE47CC5995417112BA60076F9AC21951966C8A3629B30）
  .text$mn：COFF rawptr=140, rawsize=127（实测解析 COFF section table 得到）。
- **提取公式（WO-2701 修正，替代旧公式“前 56B + FF D0 + obj[60..63]”）**：

  | 切片 | 范围 | 长度 | 内容 |
  |------|------|------|------|
  | production | obj[0x00..0x35) || obj[0x39..0x40) | 53B + 7B = 60B | 0x35..0x38 为 test-only probe 区，production 不含；0x39 起为 add rsp,0x38 + ret |
  | test | obj[0x00..0x40) | 64B | 含 probe @0x35..0x38，call 移至 0x39 |

- **逐字节验证**（本机对 obj 实际切片，SHA-256）：

  | 切片 | SHA-256 | 说明 |
  |------|---------|------|
  | production 60B | 9B6F4A7A138B3C4C5523CEDD047745C96AA83CA01614BEB703E4994DA2E1F017 | == fixture THUNK7_CODE SHA（三者闭环：fixture 字节表 == obj 提取 == SHA） |
  | test 64B | 01DC2017D8825EFD7E1C3FBE186C2FACF36FB22F2338C493C422E659476E17AE | probe @0x35、call @0x39 |

- 关键区别（指令占位，闭区间含端点）：production 字节 0x35..0x36（2B）= FF D0（call rax 直接）；test 字节 0x35..0x38（4B）= 49 89 63 48（probe），test 字节 0x39..0x3A（2B）= FF D0（call）。
- **.text$mn 完整原始字节（127B，COFF rawptr=140 / rawsize=127 提取）**：

  ```
  0000: 49 89 CB 49 8B 03 49 8B 4B 08 49 8B 53 10 4D 8B
  0010: 43 18 4D 8B 4B 20 48 83 EC 38 4D 8B 53 28 4C 89
  0020: 54 24 20 4D 8B 53 30 4C 89 54 24 28 4D 8B 53 38
  0030: 4C 89 54 24 30 49 89 63 48 FF D0 48 83 C4 38 C3
  0040: 48 8B C4 48 83 E0 0F 4C 8B 15 00 00 00 00 49 89
  0050: 42 38 49 89 0A 49 89 52 08 4D 89 42 10 4D 89 4A
  0060: 18 48 8B 44 24 28 49 89 42 20 48 8B 44 24 30 49
  0070: 89 42 28 48 8B 44 24 38 49 89 42 30 33 C0 C3
  ```

  前 obj[0x00..0x40)（64B）= thunk + probe（test 形态）；obj[0x40..0x7F)（半开区间，63B）= callee entry-stub（0x40..0x7E inclusive = 63B）
  （入口记录 rsp：mov rax,rsp / and rax,0Fh；slot 写回：mov [r11+0x38],rax 等）。

- **双流偏移分离（production / test）**：

  | 指令 | production（60B） | test（64B） |
  |------|-------------------|-------------|
  | call rax | **0x35**（FF D0） | **0x39**（FF D0） |
  | add rsp,0x38 | 0x37 | 0x3B |
  | ret | 0x3B | 0x3F |
  | probe（49 89 63 48） | —（不包含） | 0x35..0x38 |

  production 结束于 0x3B（ret，60B）；test 结束于 0x3F（ret，64B）。
  偏移起点：0x00 mov r11,rcx。

## 6. 边界声明

- local x64 ABI PASS 仅证明本机调用约定；远程执行（WPM/CreateRemoteThread/SEH/VEH）
  待 LIVE-4，本工单不构成 Windows/remote PASS。
- 未修改 crates/ 生产代码。

---
（WO-2601 原始交付绑定 639eee3；WO-2701 提取公式修正绑定 928047f；WO-2802 文字修正绑定 dea085b；WO-2902 元数据收口绑定 9589fd1 —— 历史绑定链保留，当前树绑定 9589fd1）