//! XC-XXI Step 1 页级监控宿主 (门1 实弹)
//!
//! 独立进程宿主: LoadLibraryW(候选 core.dll) -> before 快照 (目标区逐 4KB 页
//! sha256) -> GetAppVersion x10 (记录返回值) -> after 快照 -> 输出 JSON diff。
//!
//! 判定: 「运行时解密实体化」= 调用后目标页出现明文代码 (页内容变化 / 保持明文);
//! 「纯解释执行」= 调用前后目标页保持加密字节流但函数正常返回。
//!
//! 红线: NO_BYPASS=1; 不修改样品; Run 不调用 (urlmon 网络副作用, 不外发)。

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;

use windows::core::{PCSTR, PCWSTR};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};

const PAGE: usize = 0x1000;

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn sha256_hex(data: &[u8]) -> String {
    // 内联 SHA-256 (RFC 6234), 避免额外依赖。仅用于证据哈希。
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    const K: [u32; 64] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut msg = data.to_vec();
    let bitlen = (msg.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());
    let mut w = [0u32; 64];
    for chunk in msg.chunks(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }
    h.iter()
        .map(|x| format!("{x:08x}"))
        .collect::<Vec<_>>()
        .join("")
}

/// 目标区: (名称, RVA, size) — 来自 pefile 静态分析 (候选固定基址 dump 产物)
const TARGETS: &[(&str, usize, usize)] = &[
    (".text(anon)", 0x1000, 0x101940),
    (".winlice", 0x198000, 0x708000),
    (".boot", 0x8a0000, 0x511a00),
];

struct Snap {
    pages: Vec<(usize, String, [u8; 16])>,
}

fn snapshot(base: u64, rva: usize, size: usize) -> Snap {
    let va = base as usize + rva;
    let mut pages = Vec::new();
    let mut off = 0;
    while off < size {
        let chunk = size - off;
        let n = if chunk > PAGE { PAGE } else { chunk };
        let buf = unsafe { std::slice::from_raw_parts((va as *const u8).add(off), n) };
        let h = sha256_hex(buf);
        let mut head = [0u8; 16];
        for (i, b) in buf.iter().take(16).enumerate() {
            head[i] = *b;
        }
        pages.push((off, h, head));
        off += n;
    }
    Snap { pages }
}

fn main() {
    let _ = env::set_var("NO_BYPASS", "1");
    let _ = env::set_var("MIDA_GTO_NO_BYPASS", "1");

    let dll = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: xx21_monitor.exe <core.dll> <outdir>");
        std::process::exit(2);
    });
    let outdir = env::args().nth(2).unwrap_or_else(|| ".".into());

    let dllw = wide(OsStr::new(&dll));
    // SAFETY: dllw valid wide string.
    let hmod = match unsafe { LoadLibraryW(PCWSTR(dllw.as_ptr())) } {
        Ok(h) => h,
        Err(e) => {
            eprintln!("LoadLibraryW failed: {e}");
            std::process::exit(1);
        }
    };
    let base = hmod.0 as u64;
    println!("base=0x{base:X}");

    // 解析导出
    let ver_name: Vec<u8> = b"GetAppVersion\0".to_vec();
    // SAFETY: valid C string.
    let ver_ptr = unsafe { GetProcAddress(hmod, PCSTR(ver_name.as_ptr())) };
    let run_name: Vec<u8> = b"Run\0".to_vec();
    // SAFETY: valid C string.
    let run_ptr = unsafe { GetProcAddress(hmod, PCSTR(run_name.as_ptr())) };
    println!(
        "exports: GetAppVersion=0x{:X} Run=0x{:X}",
        ver_ptr.map(|p| p as usize).unwrap_or(0),
        run_ptr.map(|p| p as usize).unwrap_or(0)
    );

    // before 快照
    let mut before = Vec::new();
    for &(name, rva, size) in TARGETS {
        before.push((name, rva, size, snapshot(base, rva, size)));
    }

    // 触发 GetAppVersion x10
    let mut returns: Vec<String> = Vec::new();
    if let Some(p) = ver_ptr {
        let f: extern "system" fn() -> u64 = unsafe { std::mem::transmute(p as usize) };
        for _ in 0..10 {
            let r = unsafe { f() };
            returns.push(format!("0x{r:X}"));
        }
    }
    println!("GetAppVersion x10: {:?}", returns);

    // after 快照
    let mut after = Vec::new();
    for &(name, rva, size) in TARGETS {
        after.push((name, rva, size, snapshot(base, rva, size)));
    }

    // diff
    let mut out = String::new();
    out.push_str(&format!("{{\n  \"base\": \"0x{base:X}\",\n"));
    out.push_str(&format!("  \"getappversion_returns\": {:?},\n", returns));
    out.push_str("  \"page_diff\": {\n");
    let mut first_target = true;
    for i in 0..before.len() {
        let (name, _rva, _size, b) = &before[i];
        let (_, _, _, a) = &after[i];
        if !first_target {
            out.push_str(",\n");
        }
        first_target = false;
        let mut changed = Vec::new();
        let mut b_plain = 0usize;
        let mut a_plain = 0usize;
        for j in 0..b.pages.len() {
            let bp = &b.pages[j];
            let ap = &a.pages[j];
            if bp.1 != ap.1 {
                changed.push(format!(
                    "{{off=0x{:X}, before={}, after={}, before_head={}, after_head={}}}",
                    bp.0,
                    &bp.1[..16],
                    &ap.1[..16],
                    bp.2.iter()
                        .map(|x| format!("{x:02x}"))
                        .collect::<Vec<_>>()
                        .join(""),
                    ap.2.iter()
                        .map(|x| format!("{x:02x}"))
                        .collect::<Vec<_>>()
                        .join("")
                ));
            }
            // 简单明文启发: 首字节 == 0x40/0x48/0x55/0x53/0xE9/0x49 等常见 x64 序言
            if bp.2[0] == 0x40
                || bp.2[0] == 0x48
                || bp.2[0] == 0x55
                || bp.2[0] == 0x53
                || bp.2[0] == 0xe9
                || bp.2[0] == 0x49
                || bp.2[0] == 0x4c
            {
                b_plain += 1;
            }
            if ap.2[0] == 0x40
                || ap.2[0] == 0x48
                || ap.2[0] == 0x55
                || ap.2[0] == 0x53
                || ap.2[0] == 0xe9
                || ap.2[0] == 0x49
                || ap.2[0] == 0x4c
            {
                a_plain += 1;
            }
        }
        out.push_str(&format!(
            "    \"{name}\": {{\"pages\": {}, \"changed\": {}, \"before_plain_heuristic\": {b_plain}, \"after_plain_heuristic\": {a_plain}, \"changed_pages\": [{}]}}",
            b.pages.len(),
            changed.len(),
            changed[..changed.len().min(30)].join(", ")
        ));
    }
    out.push_str("\n  }\n}\n");

    fs::create_dir_all(&outdir).ok();
    let outpath = Path::new(&outdir).join("step1_pagemonitor.json");
    fs::write(&outpath, &out).ok();
    print!("{out}");
}
