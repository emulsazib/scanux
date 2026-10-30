//! Static features for PE and ELF files. The order of FEATURE_NAMES is a wire
//! contract with edge-ml/training/features.py and every trained model. Change
//! both together and bump the model version.

use goblin::Object;

pub const FEATURE_NAMES: [&str; 21] = [
    "size_log2",
    "entropy",
    "is_pe",
    "is_elf",
    "is_64bit",
    "is_dll",
    "num_sections",
    "max_section_entropy",
    "num_wx_sections",
    "num_imports",
    "num_import_dlls",
    "suspicious_imports",
    "has_signature",
    "has_debug",
    "has_tls",
    "overlay_ratio",
    "packer_section",
    "entry_outside_code",
    "timestamp_anomaly",
    "num_exports",
    "url_count",
];

pub const NUM_FEATURES: usize = FEATURE_NAMES.len();

/// Imports associated with injection, credential dumping, encryption, or download-and-execute.
pub const SUSPICIOUS_IMPORTS: &[&str] = &[
    "virtualallocex", "writeprocessmemory", "createremotethread", "ntunmapviewofsection",
    "zwunmapviewofsection", "setwindowshookexa", "setwindowshookexw", "queueuserapc",
    "ntqueueapcthread", "readprocessmemory", "minidumpwritedump", "cryptencrypt",
    "bcryptencrypt", "adjusttokenprivileges", "urldownloadtofilea", "urldownloadtofilew",
    "winexec", "isdebuggerpresent", "setthreadcontext", "resumethread",
];

const PACKER_SECTIONS: &[&str] = &["upx0", "upx1", "upx2", ".aspack", ".adata", ".petite", ".packed", ".themida", ".vmp0", ".vmp1", "mpress1"];

#[derive(Debug, Clone)]
pub struct Features {
    pub values: [f32; NUM_FEATURES],
}

pub fn entropy(data: &[u8]) -> f32 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    data.iter().for_each(|b| counts[*b as usize] += 1);
    let n = data.len() as f32;
    counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f32 / n;
        -p * p.log2()
    }).sum()
}

fn count_urls(data: &[u8]) -> f32 {
    let n = data.windows(7).filter(|w| w == b"http://" || w.starts_with(b"https:/")).count();
    n.min(50) as f32
}

fn slice(data: &[u8], off: usize, len: usize) -> &[u8] {
    let start = off.min(data.len());
    &data[start..start.saturating_add(len).min(data.len())]
}

/// Returns None for anything that is not a parseable PE or ELF.
pub fn extract(data: &[u8]) -> Option<Features> {
    let mut v = [0f32; NUM_FEATURES];
    let set = |v: &mut [f32; NUM_FEATURES], name: &str, x: f32| {
        let i = FEATURE_NAMES.iter().position(|n| *n == name).expect("feature name");
        v[i] = x;
    };
    set(&mut v, "size_log2", (data.len().max(1) as f32).log2());
    set(&mut v, "entropy", entropy(data));
    set(&mut v, "url_count", count_urls(data));

    match Object::parse(data).ok()? {
        Object::PE(pe) => {
            set(&mut v, "is_pe", 1.0);
            set(&mut v, "is_64bit", pe.is_64 as u8 as f32);
            set(&mut v, "is_dll", pe.is_lib as u8 as f32);
            set(&mut v, "num_sections", pe.sections.len() as f32);
            let mut max_ent: f32 = 0.0;
            let mut wx = 0;
            let mut packer = 0.0;
            let mut raw_end = 0usize;
            let mut entry_ok = false;
            let entry = pe.entry;
            let n = pe.sections.len();
            for (i, s) in pe.sections.iter().enumerate() {
                let body = slice(data, s.pointer_to_raw_data as usize, s.size_of_raw_data as usize);
                max_ent = max_ent.max(entropy(body));
                let c = s.characteristics;
                const CODE: u32 = 0x20;
                const EXEC: u32 = 0x2000_0000;
                const WRITE: u32 = 0x8000_0000;
                if c & EXEC != 0 && c & WRITE != 0 {
                    wx += 1;
                }
                let name = String::from_utf8_lossy(&s.name).trim_end_matches('\0').to_lowercase();
                if PACKER_SECTIONS.contains(&name.as_str()) {
                    packer = 1.0;
                }
                raw_end = raw_end.max((s.pointer_to_raw_data + s.size_of_raw_data) as usize);
                let vsize = s.virtual_size.max(s.size_of_raw_data);
                if entry >= s.virtual_address && entry < s.virtual_address + vsize {
                    entry_ok = c & CODE != 0 && (i + 1 < n || n == 1);
                }
            }
            set(&mut v, "max_section_entropy", max_ent);
            set(&mut v, "num_wx_sections", wx as f32);
            set(&mut v, "packer_section", packer);
            set(&mut v, "entry_outside_code", if entry_ok { 0.0 } else { 1.0 });
            let overlay = data.len().saturating_sub(raw_end) as f32 / data.len().max(1) as f32;
            set(&mut v, "overlay_ratio", overlay);
            set(&mut v, "num_imports", pe.imports.len() as f32);
            set(&mut v, "num_import_dlls", pe.libraries.len() as f32);
            let sus = pe
                .imports
                .iter()
                .filter(|i| SUSPICIOUS_IMPORTS.contains(&i.name.to_lowercase().as_str()))
                .count();
            set(&mut v, "suspicious_imports", sus as f32);
            set(&mut v, "num_exports", pe.exports.len() as f32);
            let signed = pe
                .header
                .optional_header
                .and_then(|oh| oh.data_directories.get_certificate_table().copied())
                .is_some_and(|d| d.size > 0);
            set(&mut v, "has_signature", signed as u8 as f32);
            set(&mut v, "has_debug", pe.debug_data.is_some() as u8 as f32);
            set(&mut v, "has_tls", pe.tls_data.is_some() as u8 as f32);
            let ts = pe.header.coff_header.time_date_stamp;
            set(&mut v, "timestamp_anomaly", (ts == 0 || ts > 1_900_000_000) as u8 as f32);
        }
        Object::Elf(elf) => {
            set(&mut v, "is_elf", 1.0);
            set(&mut v, "is_64bit", elf.is_64 as u8 as f32);
            set(&mut v, "is_dll", (elf.header.e_type == goblin::elf::header::ET_DYN && elf.interpreter.is_none()) as u8 as f32);
            set(&mut v, "num_sections", elf.section_headers.len() as f32);
            let mut max_ent: f32 = 0.0;
            let mut wx = 0;
            for sh in &elf.section_headers {
                if sh.sh_type != goblin::elf::section_header::SHT_NOBITS {
                    max_ent = max_ent.max(entropy(slice(data, sh.sh_offset as usize, sh.sh_size as usize)));
                }
            }
            for ph in &elf.program_headers {
                if ph.p_type == goblin::elf::program_header::PT_LOAD && ph.is_write() && ph.is_executable() {
                    wx += 1;
                }
            }
            set(&mut v, "max_section_entropy", max_ent);
            set(&mut v, "num_wx_sections", wx as f32);
            set(&mut v, "num_imports", elf.dynsyms.iter().filter(|s| s.is_import()).count() as f32);
            set(&mut v, "num_import_dlls", elf.libraries.len() as f32);
            set(&mut v, "packer_section", (elf.section_headers.is_empty() && !elf.program_headers.is_empty()) as u8 as f32);
        }
        _ => return None,
    }
    Some(Features { values: v })
}
