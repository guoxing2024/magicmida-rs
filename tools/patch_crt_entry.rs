use std::env;
use std::fs;

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(data[offset..offset + 2].try_into().unwrap())
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap())
}

fn write_u32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn parse_hex(value: &str) -> u32 {
    u32::from_str_radix(value.trim_start_matches("0x"), 16).unwrap()
}

fn align_up(value: u32, alignment: u32) -> u32 {
    (value + alignment - 1) & !(alignment - 1)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    assert!(
        args.len() == 5 || args.len() == 6,
        "usage: patch_crt_entry INPUT OUTPUT SECURITY_RVA SCRT_RVA [--zero-data]"
    );

    let mut data = fs::read(&args[1]).unwrap();
    let security_rva = parse_hex(&args[3]);
    let scrt_rva = parse_hex(&args[4]);

    let pe_offset = read_u32(&data, 0x3c) as usize;
    assert_eq!(&data[pe_offset..pe_offset + 4], b"PE\0\0");
    let section_count = read_u16(&data, pe_offset + 6) as usize;
    let optional_size = read_u16(&data, pe_offset + 20) as usize;
    let optional = pe_offset + 24;
    assert_eq!(read_u16(&data, optional), 0x20b, "expected PE32+");
    let file_alignment = read_u32(&data, optional + 36);
    let section_table = optional + optional_size;

    let mut text_header = None;
    let mut data_header = None;
    for index in 0..section_count {
        let header = section_table + index * 40;
        if &data[header..header + 5] == b".text" {
            text_header = Some(header);
        } else if &data[header..header + 5] == b".data" {
            data_header = Some(header);
        }
    }
    let text = text_header.expect("missing .text section");
    let virtual_size = read_u32(&data, text + 8);
    let virtual_address = read_u32(&data, text + 12);
    let raw_size = read_u32(&data, text + 16);
    let raw_offset = read_u32(&data, text + 20);

    let stub_rva = align_up(virtual_address + virtual_size, 16);
    let stub_offset = raw_offset + (stub_rva - virtual_address);
    let stub_len = 18u32;
    assert!(stub_offset + stub_len <= raw_offset + raw_size, "no room in .text raw padding");

    let mut stub = [
        0x48, 0x83, 0xec, 0x28,
        0xe8, 0, 0, 0, 0,
        0x48, 0x83, 0xc4, 0x28,
        0xe9, 0, 0, 0, 0,
    ];
    let call_disp = security_rva as i64 - (stub_rva + 9) as i64;
    let jmp_disp = scrt_rva as i64 - (stub_rva + 18) as i64;
    stub[5..9].copy_from_slice(&(call_disp as i32).to_le_bytes());
    stub[14..18].copy_from_slice(&(jmp_disp as i32).to_le_bytes());

    let start = stub_offset as usize;
    data[start..start + stub.len()].copy_from_slice(&stub);
    write_u32(&mut data, optional + 16, stub_rva);
    write_u32(&mut data, text + 8, stub_rva + stub_len - virtual_address);

    if args.get(5).map(String::as_str) == Some("--zero-data") {
        let data_section = data_header.expect("missing .data section");
        let data_raw_size = read_u32(&data, data_section + 16) as usize;
        let data_raw_offset = read_u32(&data, data_section + 20) as usize;
        data[data_raw_offset..data_raw_offset + data_raw_size].fill(0);
        println!("zeroed .data at file offset={data_raw_offset:#x}, size={data_raw_size:#x}");
    }

    fs::write(&args[2], data).unwrap();
    println!("stub RVA={stub_rva:#x}, file offset={stub_offset:#x}, file alignment={file_alignment:#x}");
}
