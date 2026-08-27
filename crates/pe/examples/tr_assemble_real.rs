//! T2 Phase B 真实组装入口（手工运行；需要金库组件在场）。
//!
//! 运行: `cargo run -p mida-pe --example tr_assemble_real --offline`
//!
//! 输出: gto_tr_t2\candidate\tr_candidate_v1.exe + 自解析验证打印。

// This is a hand-run example binary whose sole purpose is to print its
// assembly plan and self-check to stdout; the deny-level print_stdout lint is
// waived at the crate root for that reason.
#![allow(clippy::print_stdout)]

use std::path::Path;

const COMPONENTS: &str = r"D:\MidaVault\lab\evidence\gto_tr_t2\components";
const PROVENANCE: &str = r"D:\MidaVault\lab\evidence\gto_tr_t2\provenance.json";
const OUT: &str = r"D:\MidaVault\lab\evidence\gto_tr_t2\candidate\tr_candidate_v1.exe";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let comps = Path::new(COMPONENTS);
    let prov = Path::new(PROVENANCE);
    let out = Path::new(OUT);

    let (plan, meta) = mida_pe::rebuild::tr_surface::build_tr_surface_plan(comps, prov)?;
    println!(
        "plan: {} sections | image_base={:#x} | size_of_image={:#x} | ep_tbd={} | deferred={:?}",
        meta.sections.len(),
        meta.image_base,
        meta.size_of_image,
        meta.entry_point_tbd,
        meta.deferred_directories
    );
    for s in &meta.sections {
        println!(
            "  {:<10} rva=0x{:07x} vsize=0x{:07x} sha256={}",
            s.name,
            s.rva,
            s.virtual_size,
            &s.sha256[..16.min(s.sha256.len())]
        );
    }

    let image = mida_pe::rebuild::rebuild_pe_image(&plan)?;
    if let Some(parent) = out.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(out, &image)?;
    println!(
        "candidate written: {} ({} bytes)",
        out.display(),
        image.len()
    );

    // 自解析验证
    let mz_ok = image.len() >= 2 && image[0] == b'M' && image[1] == b'Z';
    let e_lfanew =
        u32::from_le_bytes([image[0x3c], image[0x3d], image[0x3e], image[0x3f]]) as usize;
    let pe_sig = image.len() > e_lfanew + 4 && &image[e_lfanew..e_lfanew + 4] == b"PE\0\0";
    let nsec = u16::from_le_bytes([image[e_lfanew + 6], image[e_lfanew + 7]]);
    println!("self-check: MZ={mz_ok} e_lfanew={e_lfanew:#x} PE_sig={pe_sig} nsec={nsec}");
    if !mz_ok || !pe_sig || nsec != meta.sections.len() as u16 {
        return Err("self-check failed".into());
    }
    Ok(())
}
