//! Pure export directory builder for PE reconstruction.
//!
//! Emits `IMAGE_EXPORT_DIRECTORY` plus EAT / name / ordinal tables and string
//! payloads as a single contiguous buffer. Accepts only typed PE values and
//! bytes — no host filesystem, Win32, or packer policy.

use crate::error::PeError;

/// Size of `IMAGE_EXPORT_DIRECTORY` in bytes.
pub const EXPORT_DIRECTORY_SIZE: usize = 40;

/// One exported function (by name and/or ordinal slot).
#[derive(Debug, Clone)]
pub struct ExportFunction {
    /// Export name (`None` = ordinal-only; still occupies an EAT slot).
    pub name: Option<String>,
    /// Function RVA in the final image (or forwarder RVA if treated as data).
    pub rva: u32,
}

/// Builder for a pure `.edata` export section.
#[derive(Debug, Clone)]
pub struct ExportTableBuilder {
    /// DLL name written into the export directory `Name` field.
    pub dll_name: String,
    /// Ordinal base (`Base` field). First EAT slot is this ordinal.
    pub ordinal_base: u32,
    /// Ordered EAT entries (index 0 → ordinal `ordinal_base`).
    pub functions: Vec<ExportFunction>,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub characteristics: u32,
}

impl Default for ExportTableBuilder {
    fn default() -> Self {
        Self {
            dll_name: "module.dll".into(),
            ordinal_base: 1,
            functions: Vec::new(),
            time_date_stamp: 0,
            major_version: 0,
            minor_version: 0,
            characteristics: 0,
        }
    }
}

impl ExportTableBuilder {
    /// Create a builder with the given DLL name and default ordinal base 1.
    #[must_use]
    pub fn new(dll_name: impl Into<String>) -> Self {
        Self {
            dll_name: dll_name.into(),
            ..Self::default()
        }
    }

    /// Append a named export at the next EAT slot.
    pub fn add_export(&mut self, name: impl Into<String>, rva: u32) -> &mut Self {
        self.functions.push(ExportFunction {
            name: Some(name.into()),
            rva,
        });
        self
    }

    /// Append an ordinal-only export (no name pointer).
    pub fn add_ordinal_export(&mut self, rva: u32) -> &mut Self {
        self.functions.push(ExportFunction { name: None, rva });
        self
    }

    /// Number of EAT slots.
    #[must_use]
    pub fn function_count(&self) -> usize {
        self.functions.len()
    }

    /// Number of named exports.
    #[must_use]
    pub fn name_count(&self) -> usize {
        self.functions.iter().filter(|f| f.name.is_some()).count()
    }

    /// Build section bytes for placement at `section_va`.
    ///
    /// Layout:
    /// ```text
    /// +0x00  IMAGE_EXPORT_DIRECTORY (40)
    /// +0x28  AddressOfFunctions  (NumberOfFunctions * 4)
    ///        AddressOfNames      (NumberOfNames * 4)
    ///        AddressOfNameOrdinals (NumberOfNames * 2)
    ///        DLL name + function name strings (NUL-terminated)
    /// ```
    ///
    /// Returns `(section_data, directory_size)` where `directory_size` is the
    /// full export blob length (standard PE practice for the export DD size).
    pub fn build_section_data(&self, section_va: u32) -> Result<(Vec<u8>, u32), PeError> {
        if self.functions.is_empty() {
            return Err(PeError::Parse(
                "export table requires at least one function".into(),
            ));
        }
        if self.ordinal_base == 0 {
            return Err(PeError::Parse(
                "export ordinal base must be non-zero".into(),
            ));
        }

        let n_funcs = self.functions.len();
        // Named exports keep source order for deterministic emit; PE loaders
        // accept unsorted names for structural validity (binary search is best-effort).
        let named: Vec<(usize, &str)> = self
            .functions
            .iter()
            .enumerate()
            .filter_map(|(i, f)| f.name.as_deref().map(|n| (i, n)))
            .collect();
        let n_names = named.len();

        let eat_off = EXPORT_DIRECTORY_SIZE;
        let names_off =
            eat_off
                .checked_add(n_funcs.checked_mul(4).ok_or_else(|| {
                    PeError::Parse("export AddressOfFunctions size overflow".into())
                })?)
                .ok_or_else(|| PeError::Parse("export names offset overflow".into()))?;
        let ords_off = names_off
            .checked_add(
                n_names
                    .checked_mul(4)
                    .ok_or_else(|| PeError::Parse("export AddressOfNames size overflow".into()))?,
            )
            .ok_or_else(|| PeError::Parse("export ordinals offset overflow".into()))?;
        let strings_off = ords_off
            .checked_add(n_names.checked_mul(2).ok_or_else(|| {
                PeError::Parse("export AddressOfNameOrdinals size overflow".into())
            })?)
            .ok_or_else(|| PeError::Parse("export strings offset overflow".into()))?;

        // Precompute string table size.
        let dll_name_bytes = self.dll_name.as_bytes();
        let mut string_bytes = dll_name_bytes
            .len()
            .checked_add(1)
            .ok_or_else(|| PeError::Parse("export dll name length overflow".into()))?;
        for (_, name) in &named {
            string_bytes = string_bytes
                .checked_add(name.len())
                .and_then(|v| v.checked_add(1))
                .ok_or_else(|| PeError::Parse("export name strings overflow".into()))?;
        }

        let total = strings_off
            .checked_add(string_bytes)
            .ok_or_else(|| PeError::Parse("export section size overflow".into()))?;
        if total > u32::MAX as usize {
            return Err(PeError::Parse("export section exceeds u32".into()));
        }

        let mut data = vec![0u8; total];
        let section_va = section_va;

        // ---- Strings first so we know RVAs ----
        let mut cursor = strings_off;
        let dll_name_rva = section_va
            .checked_add(cursor as u32)
            .ok_or_else(|| PeError::Parse("export dll name RVA overflow".into()))?;
        data[cursor..cursor + dll_name_bytes.len()].copy_from_slice(dll_name_bytes);
        cursor += dll_name_bytes.len() + 1; // NUL already zeroed

        let mut name_rvas: Vec<u32> = Vec::with_capacity(n_names);
        for (_, name) in &named {
            let rva = section_va
                .checked_add(cursor as u32)
                .ok_or_else(|| PeError::Parse("export function name RVA overflow".into()))?;
            name_rvas.push(rva);
            let nb = name.as_bytes();
            data[cursor..cursor + nb.len()].copy_from_slice(nb);
            cursor += nb.len() + 1;
        }
        debug_assert_eq!(cursor, total);

        // ---- EAT ----
        for (i, f) in self.functions.iter().enumerate() {
            let off = eat_off + i * 4;
            data[off..off + 4].copy_from_slice(&f.rva.to_le_bytes());
        }

        // ---- Name pointers + ordinals (EAT indices as u16) ----
        for (i, (eat_index, _)) in named.iter().enumerate() {
            let noff = names_off + i * 4;
            data[noff..noff + 4].copy_from_slice(&name_rvas[i].to_le_bytes());
            let ooff = ords_off + i * 2;
            let ord_index = u16::try_from(*eat_index)
                .map_err(|_| PeError::Parse("export name ordinal index exceeds u16".into()))?;
            data[ooff..ooff + 2].copy_from_slice(&ord_index.to_le_bytes());
        }

        // ---- IMAGE_EXPORT_DIRECTORY ----
        let eat_rva = section_va
            .checked_add(eat_off as u32)
            .ok_or_else(|| PeError::Parse("export EAT RVA overflow".into()))?;
        let names_rva = section_va
            .checked_add(names_off as u32)
            .ok_or_else(|| PeError::Parse("export names RVA overflow".into()))?;
        let ords_rva = section_va
            .checked_add(ords_off as u32)
            .ok_or_else(|| PeError::Parse("export ordinals RVA overflow".into()))?;

        write_u32(&mut data, 0, self.characteristics);
        write_u32(&mut data, 4, self.time_date_stamp);
        write_u16(&mut data, 8, self.major_version);
        write_u16(&mut data, 10, self.minor_version);
        write_u32(&mut data, 12, dll_name_rva);
        write_u32(&mut data, 16, self.ordinal_base);
        write_u32(&mut data, 20, n_funcs as u32);
        write_u32(&mut data, 24, n_names as u32);
        write_u32(&mut data, 28, eat_rva);
        write_u32(&mut data, 32, names_rva);
        write_u32(&mut data, 36, ords_rva);

        Ok((data, total as u32))
    }
}

fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn export_named_layout_round_trips_fields() {
        let mut b = ExportTableBuilder::new("sample.dll");
        b.add_export("Foo", 0x1000).add_export("Bar", 0x1010);
        let (data, size) = b.build_section_data(0x3000).expect("build");
        assert_eq!(size as usize, data.len());
        assert!(data.len() >= EXPORT_DIRECTORY_SIZE);

        let n_funcs = u32::from_le_bytes(data[20..24].try_into().unwrap());
        let n_names = u32::from_le_bytes(data[24..28].try_into().unwrap());
        assert_eq!(n_funcs, 2);
        assert_eq!(n_names, 2);

        let eat_rva = u32::from_le_bytes(data[28..32].try_into().unwrap());
        assert_eq!(eat_rva, 0x3000 + EXPORT_DIRECTORY_SIZE as u32);

        let eat_off = (eat_rva - 0x3000) as usize;
        let rva0 = u32::from_le_bytes(data[eat_off..eat_off + 4].try_into().unwrap());
        let rva1 = u32::from_le_bytes(data[eat_off + 4..eat_off + 8].try_into().unwrap());
        assert_eq!(rva0, 0x1000);
        assert_eq!(rva1, 0x1010);

        let name_dir_rva = u32::from_le_bytes(data[12..16].try_into().unwrap());
        let name_off = (name_dir_rva - 0x3000) as usize;
        let cstr = std::str::from_utf8(&data[name_off..])
            .unwrap()
            .split('\0')
            .next()
            .unwrap();
        assert_eq!(cstr, "sample.dll");
    }

    #[test]
    fn export_ordinal_only_has_zero_names() {
        let mut b = ExportTableBuilder::new("x.dll");
        b.add_ordinal_export(0x2000);
        let (data, _) = b.build_section_data(0x4000).expect("build");
        let n_names = u32::from_le_bytes(data[24..28].try_into().unwrap());
        assert_eq!(n_names, 0);
        let n_funcs = u32::from_le_bytes(data[20..24].try_into().unwrap());
        assert_eq!(n_funcs, 1);
    }

    #[test]
    fn export_empty_errors() {
        let b = ExportTableBuilder::new("x.dll");
        assert!(b.build_section_data(0x1000).is_err());
    }
}
