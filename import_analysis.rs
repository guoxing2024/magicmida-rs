// 临时测试：验证原始PE的import table是否可以完整读取并使用

use std::path::Path;

fn main() {
    let original_path = Path::new("D:/Tools/RE/dumps/runtime/启动器.exe");

    // 使用pefile读取原始PE
    let bytes = std::fs::read(original_path).unwrap();

    println!("原始PE大小: {} bytes", bytes.len());
    println!();

    // 简单的PE解析
    let pe_offset = u32::from_le_bytes([bytes[0x3C], bytes[0x3D], bytes[0x3E], bytes[0x3F]]) as usize;

    // 读取import directory
    let opt_header_offset = pe_offset + 24;
    let data_dir_offset = opt_header_offset + 112;

    let import_rva = u32::from_le_bytes([
        bytes[data_dir_offset + 8],
        bytes[data_dir_offset + 9],
        bytes[data_dir_offset + 10],
        bytes[data_dir_offset + 11],
    ]);

    println!("Import Directory RVA: 0x{:X}", import_rva);
    println!();
    println!("策略：");
    println!("1. 读取原始PE的所有import descriptors");
    println!("2. 为每个descriptor，读取DLL名称和FirstThunk RVA");
    println!("3. 读取所有imports（从OriginalFirstThunk或FirstThunk）");
    println!("4. 为每个thunk设置正确的iat_address（基于FirstThunk RVA）");
    println!("5. 这样build_import_section_no_iat就能正确分组");
}
