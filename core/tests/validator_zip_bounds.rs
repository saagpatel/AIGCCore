use aigc_core::policy::types::PolicyMode;
use aigc_core::validator::BundleValidator;
use std::io::Write;
use zip::write::{FileOptions, ZipWriter};
use zip::CompressionMethod;

const UNDERSTATED_SIZE: u32 = 100;

/// A real ZIP whose headers claim `UNDERSTATED_SIZE` bytes for an entry that
/// actually inflates to `actual_len` bytes.
fn zip_understating_sizes(actual_len: usize) -> Vec<u8> {
    let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .start_file(
            "payload.bin",
            FileOptions::<()>::default().compression_method(CompressionMethod::Deflated),
        )
        .unwrap();
    writer.write_all(&vec![0u8; actual_len]).unwrap();
    let mut bytes = writer.finish().unwrap().into_inner();
    let actual = u32::try_from(actual_len).unwrap().to_le_bytes();
    let claimed = UNDERSTATED_SIZE.to_le_bytes();
    let mut patched = 0;
    for index in 0..bytes.len().saturating_sub(30) {
        let (signature, offset) = match &bytes[index..index + 4] {
            b"PK\x03\x04" => (true, 22),
            b"PK\x01\x02" => (true, 24),
            _ => (false, 0),
        };
        if signature && bytes[index + offset..index + offset + 4] == actual {
            bytes[index + offset..index + offset + 4].copy_from_slice(&claimed);
            patched += 1;
        }
    }
    assert_eq!(patched, 2, "local and central headers both patched");
    bytes
}

#[test]
fn validate_zip_rejects_entries_that_inflate_past_their_declared_size() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("understated.zip");
    std::fs::write(&path, zip_understating_sizes(50_000)).unwrap();

    let error = BundleValidator::new_v3()
        .validate_zip(&path, PolicyMode::STRICT)
        .expect_err("a ZIP that understates its sizes must be rejected");
    let message = error.to_string();
    assert!(
        message.contains("ENTRY_SIZE_MISMATCH") || message.contains("ENTRY_READ_FAILED"),
        "{message}"
    );
}

#[test]
fn validate_zip_accepts_the_size_check_for_honest_headers() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("honest.zip");
    let mut writer = ZipWriter::new(std::fs::File::create(&path).unwrap());
    writer
        .start_file("BUNDLE_INFO.json", FileOptions::<()>::default())
        .unwrap();
    writer.write_all(b"{}").unwrap();
    writer.finish().unwrap();

    // Honest sizes pass the bounds stage and reach the content checks.
    let summary = BundleValidator::new_v3()
        .validate_zip(&path, PolicyMode::STRICT)
        .expect("size bounds hold");
    assert_eq!(summary.overall, "FAIL");
}
