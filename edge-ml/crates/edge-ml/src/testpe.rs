//! Builds minimal, valid PE32+ images for tests (no real malware needed).

pub enum Shape {
    /// .text (code, r-x) + .data (rw-), entry in .text, low entropy.
    Benign,
    /// UPX-style RWX sections, random content, entry in last section, zero
    /// timestamp, random overlay.
    PackedRwx,
}

fn lcg(seed: &mut u32) -> u8 {
    *seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
    (*seed >> 16) as u8
}

type Layout = (Vec<(&'static [u8; 8], u32)>, u32, u32, usize);

pub fn tiny_pe64(shape: Shape) -> Vec<u8> {
    let (sections, entry, ts, overlay): Layout = match shape {
        Shape::Benign => (vec![(b".text\0\0\0", 0x6000_0020), (b".data\0\0\0", 0xC000_0040)], 0x1000, 1_600_000_000, 0),
        Shape::PackedRwx => (vec![(b"UPX0\0\0\0\0", 0xE000_0020), (b"UPX1\0\0\0\0", 0xE000_0020)], 0x2010, 0, 0x400),
    };
    let random = matches!(shape, Shape::PackedRwx);
    let n = sections.len() as u16;
    let mut b = vec![0u8; 0x200];
    b[0..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    let mut o = 0x40;
    let put = |b: &mut Vec<u8>, o: &mut usize, bytes: &[u8]| {
        b[*o..*o + bytes.len()].copy_from_slice(bytes);
        *o += bytes.len();
    };
    put(&mut b, &mut o, b"PE\0\0");
    put(&mut b, &mut o, &0x8664u16.to_le_bytes());
    put(&mut b, &mut o, &n.to_le_bytes());
    put(&mut b, &mut o, &ts.to_le_bytes());
    put(&mut b, &mut o, &[0; 8]);
    put(&mut b, &mut o, &240u16.to_le_bytes());
    put(&mut b, &mut o, &0x0022u16.to_le_bytes());
    // Optional header (PE32+).
    let oh = o;
    put(&mut b, &mut o, &0x20bu16.to_le_bytes());
    put(&mut b, &mut o, &[14, 0]);
    put(&mut b, &mut o, &0x200u32.to_le_bytes()); // SizeOfCode
    put(&mut b, &mut o, &0x200u32.to_le_bytes()); // SizeOfInitializedData
    put(&mut b, &mut o, &0u32.to_le_bytes());
    put(&mut b, &mut o, &entry.to_le_bytes());
    put(&mut b, &mut o, &0x1000u32.to_le_bytes()); // BaseOfCode
    put(&mut b, &mut o, &0x1_4000_0000u64.to_le_bytes());
    put(&mut b, &mut o, &0x1000u32.to_le_bytes()); // SectionAlignment
    put(&mut b, &mut o, &0x200u32.to_le_bytes()); // FileAlignment
    put(&mut b, &mut o, &[6, 0, 0, 0, 0, 0, 0, 0, 6, 0, 0, 0]);
    put(&mut b, &mut o, &0u32.to_le_bytes()); // Win32VersionValue
    put(&mut b, &mut o, &(0x1000 * (n as u32 + 1)).to_le_bytes()); // SizeOfImage
    put(&mut b, &mut o, &0x200u32.to_le_bytes()); // SizeOfHeaders
    put(&mut b, &mut o, &0u32.to_le_bytes()); // CheckSum
    put(&mut b, &mut o, &3u16.to_le_bytes()); // Subsystem: console
    put(&mut b, &mut o, &0x8160u16.to_le_bytes());
    for v in [0x100000u64, 0x1000, 0x100000, 0x1000] {
        put(&mut b, &mut o, &v.to_le_bytes());
    }
    put(&mut b, &mut o, &0u32.to_le_bytes());
    put(&mut b, &mut o, &16u32.to_le_bytes());
    o = oh + 240; // 16 zeroed data directories
    for (i, (name, ch)) in sections.iter().enumerate() {
        let i = i as u32;
        put(&mut b, &mut o, &name[..]);
        put(&mut b, &mut o, &0x200u32.to_le_bytes()); // VirtualSize
        put(&mut b, &mut o, &(0x1000 * (i + 1)).to_le_bytes());
        put(&mut b, &mut o, &0x200u32.to_le_bytes()); // SizeOfRawData
        put(&mut b, &mut o, &(0x200 * (i + 1)).to_le_bytes());
        put(&mut b, &mut o, &[0; 12]);
        put(&mut b, &mut o, &ch.to_le_bytes());
    }
    let mut seed = 7u32;
    for i in 0..sections.len() {
        let body: Vec<u8> = (0..0x200)
            .map(|j| if random { lcg(&mut seed) } else if i == 0 { [0x48, 0x89, 0xC3, 0x90][j % 4] } else { 0 })
            .collect();
        b.extend_from_slice(&body);
    }
    b.extend((0..overlay).map(|_| lcg(&mut seed)));
    b
}
