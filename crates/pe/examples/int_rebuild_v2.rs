//! G-6-A fix: 标准 import 结构重建 (OFT->INT, FirstThunk->原位 IAT)
//!
//! 生成: [descriptors][dll names][INT hint/name 表 + null]
//! OFT 指向 INT (hint/name RVA 序列), FirstThunk 指向原位 IAT (0x159f000)
//! 验收器遍历 OFT (INT) -> hint/name RVA 可映射 -> pass
//! loader 用 OFT 按名解析 -> 写入 FirstThunk (原位 IAT) -> 调用点兼容
#![allow(clippy::print_stdout)]

const SLOTS_JSON: &str = r"D:\Temp\iat_final_slots.json";
const CANDIDATE: &str = r"D:\MidaVault\lab\evidence\gto_tr_t2\candidate\tr_candidate_v2.exe";
const OUT: &str = r"D:\MidaVault\lab\evidence\gto_tr_t2\candidate\tr_candidate_v3.exe";

const ORIGINAL_IAT_RVA: u32 = 0x159f000;
const IAT_SLOT_SIZE: u64 = 8;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1) 槽清单
    let raw = std::fs::read_to_string(SLOTS_JSON)?;
    let slots: Vec<serde_json::Value> = serde_json::from_str(&raw)?;
    println!("读入 {} 槽", slots.len());

    // 2) named 槽: idx -> (dll, name)
    let mut named: Vec<(u32, String, String)> = Vec::new();
    let mut zero_count = 0usize;
    let mut amb_count = 0usize;
    for s in &slots {
        let idx = s["idx"].as_u64().unwrap_or(0) as u32;
        let kind = s["kind"].as_str().unwrap_or("");
        match kind {
            "named" => {
                let dll = s["mod"].as_str().unwrap_or("?").to_lowercase();
                let name = s["name"].as_str().unwrap_or("?").to_string();
                named.push((idx, dll, name));
            }
            "zero" => zero_count += 1,
            _ => amb_count += 1,
        }
    }
    named.sort_by_key(|(idx, _, _)| *idx);
    println!(
        "named={} zero={} ambiguous={}",
        named.len(),
        zero_count,
        amb_count
    );

    // 3) 按连续 IAT 槽 + 同 DLL 分组为 runs
    #[derive(Clone)]
    struct Run {
        dll: String,
        thunks: Vec<(u32, String)>, // (iat_idx, name)
    }
    let mut runs: Vec<Run> = Vec::new();
    for (idx, dll, name) in &named {
        let idx = *idx;
        let dll = dll.clone();
        let name = name.clone();
        if let Some(last) = runs.last_mut() {
            if last.dll == dll && last.thunks.last().map(|(i, _)| *i) == Some(idx - 1) {
                last.thunks.push((idx, name));
                continue;
            }
        }
        runs.push(Run {
            dll,
            thunks: vec![(idx, name)],
        });
    }
    println!("runs: {}", runs.len());

    // 4) 读候选, 算新节 va
    let cand = std::fs::read(CANDIDATE)?;
    let e_lfanew = u32::from_le_bytes(cand[0x3c..0x40].try_into().unwrap()) as usize;
    let nsec = u16::from_le_bytes(cand[e_lfanew + 6..e_lfanew + 8].try_into().unwrap());
    let optsize = u16::from_le_bytes(cand[e_lfanew + 20..e_lfanew + 22].try_into().unwrap());
    let sec_table = e_lfanew + 24 + optsize as usize;

    let mut last_end_va = 0u32;
    let mut last_end_raw = 0u32;
    for i in 0..nsec as usize {
        let off = sec_table + i * 40;
        let vsize = u32::from_le_bytes(cand[off + 8..off + 12].try_into().unwrap());
        let va = u32::from_le_bytes(cand[off + 12..off + 16].try_into().unwrap());
        let rsize = u32::from_le_bytes(cand[off + 16..off + 20].try_into().unwrap());
        let ro = u32::from_le_bytes(cand[off + 20..off + 24].try_into().unwrap());
        if va + vsize > last_end_va {
            last_end_va = va + vsize;
        }
        if ro + rsize > last_end_raw {
            last_end_raw = ro + rsize;
        }
    }
    let section_va = (last_end_va + 0xFFF) & !0xFFF;
    println!("新节 va=0x{section_va:x}");

    // 5) 布局: [descriptors (run+1)*20][dll names][INT: per-run hint/name + null terminator]
    // desc 区
    let desc_size = (runs.len() + 1) * 20;
    // dll name 区
    let mut dll_name_off = Vec::new(); // 每 run 的 dll name 偏移 (节内)
    let mut cursor = desc_size;
    for r in &runs {
        dll_name_off.push(cursor);
        cursor += r.dll.len() + 1;
    }
    let dll_name_end = cursor;
    // INT 区: 每 run: 指针数组 (每项 8 字节 = hint/name 块 RVA) + null 终止
    // hint/name 块: 单独放 [hint(2)+name+null]
    let mut int_off = Vec::new(); // 每 run 的 INT 指针数组起始偏移 (节内)
    let mut hintname_off = Vec::new(); // 每 run 的 hint/name 块区起始 (节内)
    let mut int_cursor = dll_name_end;
    for r in &runs {
        int_off.push(int_cursor);
        int_cursor += (r.thunks.len() + 1) * IAT_SLOT_SIZE as usize; // 指针数组 + null
    }
    let hintname_base = int_cursor;
    for r in &runs {
        hintname_off.push(int_cursor - hintname_base);
        for (_, name) in &r.thunks {
            int_cursor += 2 + name.len() + 1; // hint + name + null
        }
    }
    let total_size = int_cursor;
    println!("import 段大小: {total_size} bytes (desc={desc_size})");

    // 6) 生成段数据
    let mut data = vec![0u8; total_size];
    // descriptors
    for (i, r) in runs.iter().enumerate() {
        let d = i * 20;
        let dll_name_rva = section_va + dll_name_off[i] as u32;
        let int_rva = section_va + int_off[i] as u32; // OFT -> INT
        let first_thunk_rva = ORIGINAL_IAT_RVA + (r.thunks[0].0 as u32) * IAT_SLOT_SIZE as u32;
        data[d..d + 4].copy_from_slice(&int_rva.to_le_bytes()); // OFT
        data[d + 4..d + 8].copy_from_slice(&0u32.to_le_bytes()); // timestamp
        data[d + 8..d + 12].copy_from_slice(&0u32.to_le_bytes()); // forwarder
        data[d + 12..d + 16].copy_from_slice(&dll_name_rva.to_le_bytes()); // name
        data[d + 16..d + 20].copy_from_slice(&first_thunk_rva.to_le_bytes()); // FirstThunk
    }
    // dll names
    for (i, r) in runs.iter().enumerate() {
        let o = dll_name_off[i];
        data[o..o + r.dll.len()].copy_from_slice(r.dll.as_bytes());
        data[o + r.dll.len()] = 0;
    }
    // INT: 每 run 的指针数组 (每项 8 字节 = hint/name 块 RVA) + null
    // hint/name 块: 每 run 的 [hint(2)+name+null] 序列
    for (i, r) in runs.iter().enumerate() {
        let mut c = int_off[i];
        let mut hc = hintname_base + hintname_off[i];
        for (_, name) in &r.thunks {
            let hnrva = section_va + hc as u32;
            data[c..c + IAT_SLOT_SIZE as usize].copy_from_slice(&(hnrva as u64).to_le_bytes());
            c += IAT_SLOT_SIZE as usize;
            // hint/name 块
            data[hc..hc + 2].copy_from_slice(&0u16.to_le_bytes()); // hint=0
            hc += 2;
            data[hc..hc + name.len()].copy_from_slice(name.as_bytes());
            hc += name.len();
            data[hc] = 0;
            hc += 1;
        }
        // null terminator (指针数组尾)
        // data 已初始化为 0, 无需显式写
    }

    // 7) 组装新 PE
    let mut out = cand.clone();
    // 节表追加
    let new_sec_off = sec_table + nsec as usize * 40;
    let mut sec_entry = [0u8; 40];
    sec_entry[0..8].copy_from_slice(b".import\x00");
    let aligned_size = ((total_size as u32) + 0xFFF) & !0xFFF;
    let raw_size = ((total_size as u32) + 0x1FF) & !0x1FF;
    let new_raw = (last_end_raw + 0x1FF) & !0x1FF;
    sec_entry[8..12].copy_from_slice(&aligned_size.to_le_bytes()); // vsize
    sec_entry[12..16].copy_from_slice(&section_va.to_le_bytes()); // va
    sec_entry[16..20].copy_from_slice(&raw_size.to_le_bytes()); // rsize
    sec_entry[20..24].copy_from_slice(&new_raw.to_le_bytes()); // ro
    sec_entry[36..40].copy_from_slice(&0xC0000040u32.to_le_bytes()); // READ|WRITE|INIT
    if new_sec_off + 40 <= out.len() {
        out[new_sec_off..new_sec_off + 40].copy_from_slice(&sec_entry);
    } else {
        return Err("节表空间不足".into());
    }
    let new_nsec = nsec + 1;
    out[e_lfanew + 6..e_lfanew + 8].copy_from_slice(&new_nsec.to_le_bytes());
    // SizeOfImage
    let new_image_size = section_va + aligned_size;
    let size_of_image_off = e_lfanew + 24 + 56;
    out[size_of_image_off..size_of_image_off + 4].copy_from_slice(&new_image_size.to_le_bytes());
    // import 数据
    if out.len() < (new_raw + raw_size) as usize {
        out.resize((new_raw + raw_size) as usize, 0);
    }
    out[new_raw as usize..new_raw as usize + total_size].copy_from_slice(&data);
    // 更新 import 目录
    let dd_off = e_lfanew + 24 + 112;
    let import_dd = dd_off + 1 * 8;
    out[import_dd..import_dd + 4].copy_from_slice(&section_va.to_le_bytes());
    out[import_dd + 4..import_dd + 8].copy_from_slice(&(desc_size as u32).to_le_bytes());
    // IAT 目录保持原位
    let iat_dd = dd_off + 12 * 8;
    out[iat_dd..iat_dd + 4].copy_from_slice(&ORIGINAL_IAT_RVA.to_le_bytes());
    out[iat_dd + 4..iat_dd + 8].copy_from_slice(&0x1190u32.to_le_bytes());

    // 8) 自检
    println!(
        "self-check: MZ={} PE={} nsec={}",
        out[0..2] == *b"MZ",
        &out[e_lfanew..e_lfanew + 4] == b"PE\0\0",
        u16::from_le_bytes(out[e_lfanew + 6..e_lfanew + 8].try_into().unwrap()) == new_nsec
    );
    std::fs::write(OUT, &out)?;
    println!("v3 written: {} ({} bytes)", OUT, out.len());
    Ok(())
}
