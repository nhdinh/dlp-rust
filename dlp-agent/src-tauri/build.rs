fn main() {
    // Write a minimal valid ICO using raw BMP DIB format that the
    // installed RC.EXE (10.0.10011.16384) accepts.
    write_ico();

    // Run tauri-build normally (compiles Rust code, doesn't compile resources here).
    tauri_build::build();
}

/// Writes a 16x16 32-bit BGRA ICO to icons/icon.ico.
///
/// The ICO uses BMP DIB format (not PNG) which is accepted by the
/// Windows SDK 10 RC.EXE version in use (10.0.10011.16384).
fn write_ico() {
    let manifest_dir = std::env!("CARGO_MANIFEST_DIR");
    let icon_path = std::path::Path::new(manifest_dir)
        .join("icons")
        .join("icon.ico");

    // 16x16 pixels — BGRA (bottom-up), no compression.
    let mut pixels: Vec<u8> = Vec::with_capacity(16 * 16 * 4);
    // Row 0 = bottom scanline (DIB is bottom-up).
    for _y in 0..16u32 {
        for _x in 0..16u32 {
            // DLP brand blue: BGRA = (204, 102, 0, 255)
            pixels.extend_from_slice(&[0xCC, 0x66, 0x00, 0xFF]);
        }
    }

    // AND mask: 16 pixels = 2 bytes per row, rows must be DWORD-aligned.
    // 16 pixels = 2 bytes; DWORD-aligned = 4 bytes per row.
    let and_mask: Vec<u8> = vec![0x00; 16 * 4];

    // ICO file:
    // 6 bytes: ICONDIR (reserved=0, type=1, count=1)
    // 16 bytes: ICONDIRENTRY (w=16, h=16, colors=0, planes=1, bpp=32, size, offset=22)
    // 40 bytes: BITMAPINFOHEADER (biSize=40, biWidth=16, biHeight=32, biPlanes=1, biBitCount=32, ...)
    // N bytes: XOR mask (16*16*4 = 1024 bytes)
    // M bytes: AND mask (16*4 = 64 bytes)

    let xor_size = pixels.len(); // 1024
    let and_size = and_mask.len(); // 64
    let bmp_size = 40 + xor_size + and_size; // 1128
    let ico_size = 6 + 16 + bmp_size; // 1150

    let mut ico: Vec<u8> = Vec::with_capacity(ico_size);

    // ICONDIR
    ico.extend_from_slice(&0u16.to_le_bytes()); // reserved
    ico.extend_from_slice(&1u16.to_le_bytes()); // type = ICO
    ico.extend_from_slice(&1u16.to_le_bytes()); // count = 1

    // ICONDIRENTRY
    ico.push(16); // width
    ico.push(16); // height
    ico.push(0); // colors (0 = no palette)
    ico.push(0); // reserved
    ico.extend_from_slice(&1u16.to_le_bytes()); // planes
    ico.extend_from_slice(&32u16.to_le_bytes()); // bit count
    ico.extend_from_slice(&(bmp_size as u32).to_le_bytes()); // size of image
    ico.extend_from_slice(&22u32.to_le_bytes()); // offset = 6 + 16

    // BITMAPINFOHEADER (biHeight = 2 * actual for XOR + AND masks)
    ico.extend_from_slice(&40u32.to_le_bytes()); // biSize
    ico.extend_from_slice(&16i32.to_le_bytes()); // biWidth
    ico.extend_from_slice(&32i32.to_le_bytes()); // biHeight (XOR + AND)
    ico.extend_from_slice(&1u16.to_le_bytes()); // biPlanes
    ico.extend_from_slice(&32u16.to_le_bytes()); // biBitCount
    ico.extend_from_slice(&0u32.to_le_bytes()); // biCompression = BI_RGB
    ico.extend_from_slice(&((xor_size + and_size) as u32).to_le_bytes()); // biSizeImage
    ico.extend_from_slice(&0i32.to_le_bytes()); // biXPelsPerMeter
    ico.extend_from_slice(&0i32.to_le_bytes()); // biYPelsPerMeter
    ico.extend_from_slice(&0u32.to_le_bytes()); // biClrUsed
    ico.extend_from_slice(&0u32.to_le_bytes()); // biClrImportant

    // XOR mask (BGRA pixels)
    ico.extend_from_slice(&pixels);

    // AND mask
    ico.extend_from_slice(&and_mask);

    assert_eq!(ico.len(), ico_size);
    std::fs::write(&icon_path, ico).ok();
}
