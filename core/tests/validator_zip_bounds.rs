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

/// A one-entry ZIP named `name`. When `corrupt_utf8` is set, the UTF-8 bytes of
/// "é" in both headers become 0xFF 0xFE, so the stored name is no longer UTF-8.
fn zip_with_entry_name(name: &str, corrupt_utf8: bool) -> Vec<u8> {
    let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
    writer
        .start_file(name, FileOptions::<()>::default())
        .unwrap();
    writer.write_all(b"{}").unwrap();
    let mut bytes = writer.finish().unwrap().into_inner();
    if corrupt_utf8 {
        let accent = "é".as_bytes();
        let mut patched = 0;
        for index in 0..=bytes.len() - accent.len() {
            if &bytes[index..index + accent.len()] == accent {
                bytes[index..index + accent.len()].copy_from_slice(&[0xFF, 0xFE]);
                patched += 1;
            }
        }
        assert_eq!(patched, 2, "local and central header names both patched");
    }
    bytes
}

#[test]
fn validate_zip_reads_utf8_entry_names() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("utf8-name.zip");
    std::fs::write(&path, zip_with_entry_name("données.json", false)).unwrap();

    // A well-formed UTF-8 name passes the archive stages and reaches the content checks.
    let summary = BundleValidator::new_v3()
        .validate_zip(&path, PolicyMode::STRICT)
        .expect("a UTF-8 entry name is readable");
    assert_eq!(summary.overall, "FAIL");
}

#[test]
fn validate_zip_decodes_non_utf8_entry_names_as_cp437() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("cp437-name.zip");
    std::fs::write(&path, zip_with_entry_name("données.json", true)).unwrap();

    // zip 9 falls back to CP437 for names that are not UTF-8, so the archive stages
    // still read every entry and the bundle is judged on its contents.
    let summary = BundleValidator::new_v3()
        .validate_zip(&path, PolicyMode::STRICT)
        .expect("a non-UTF-8 entry name decodes via CP437");
    assert_eq!(summary.overall, "FAIL");
}
