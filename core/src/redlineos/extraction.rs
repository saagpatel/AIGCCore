use crate::error::{CoreError, CoreResult};
use crate::redlineos::model::{ExtractedContract, PageLayout};
use sha2::{Sha256, Digest};

/// Extract text and metadata from contract PDF
///
/// For MVP: Simple text extraction from PDF stream
/// Future: Full pdfium-render integration for spatial data
pub fn extract_contract_text(
    pdf_bytes: &[u8],
    extraction_mode: &str,
) -> CoreResult<ExtractedContract> {
    if pdf_bytes.is_empty() {
        return Err(CoreError::InvalidInput("Empty PDF bytes".to_string()));
    }

    // Validate PDF header
    if !pdf_bytes.starts_with(b"%PDF") {
        return Err(CoreError::InvalidInput("Invalid PDF format".to_string()));
    }

    let source_hash = sha256_hex(pdf_bytes);
    let artifact_id = format!("a_contract_{}", &source_hash[..8]);

    // Extract text from PDF stream objects
    // Simple approach: find text between BT/ET markers
    let extracted_text = extract_text_from_stream(pdf_bytes)?;

    if extracted_text.trim().is_empty() {
        return Err(CoreError::InvalidInput("No text found in PDF".to_string()));
    }

    let page_count = estimate_page_count(pdf_bytes);

    let extraction_confidence = match extraction_mode {
        "NATIVE_PDF" => 0.98,  // Native PDFs have high confidence
        "OCR" => 0.85,          // OCR is lower confidence
        _ => 0.80,
    };

    // For MVP, spatial_data is basic (would require full pdfium integration)
    let spatial_data = Some(vec![PageLayout {
        page_num: 1,
        width_points: 612.0,
        height_points: 792.0,
        text_blocks: vec![],  // Would be populated with full extraction
    }]);

    Ok(ExtractedContract {
        artifact_id,
        source_bytes_hash: source_hash,
        extracted_text,
        page_count,
        extraction_confidence,
        spatial_data,
    })
}

/// Extract text content from PDF stream objects
fn extract_text_from_stream(pdf_bytes: &[u8]) -> CoreResult<String> {
    // Find text between BT (begin text) and ET (end text) operators
    let pdf_str = String::from_utf8_lossy(pdf_bytes);
    let mut extracted = String::new();

    let mut in_text_object = false;
    let mut current_text = String::new();

    for line in pdf_str.lines() {
        if line.contains("BT") {
            in_text_object = true;
        } else if line.contains("ET") {
            in_text_object = false;
            if !current_text.is_empty() {
                extracted.push_str(&current_text);
                extracted.push('\n');
                current_text.clear();
            }
        } else if in_text_object && line.contains("Tj") {
            // Extract text from Tj operator (show text)
            if let Some(start) = line.find('(') {
                if let Some(end) = line[start + 1..].find(')') {
                    let text = &line[start + 1..start + 1 + end];
                    current_text.push_str(text);
                    current_text.push(' ');
                }
            }
        }
    }

    Ok(extracted)
}

/// Estimate page count from PDF objects
fn estimate_page_count(pdf_bytes: &[u8]) -> usize {
    let pdf_str = String::from_utf8_lossy(pdf_bytes);

    // Simple heuristic: count /Type /Page occurrences
    pdf_str.matches("/Type /Page").count().max(1)
}

/// SHA-256 hash of bytes as hex string
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_invalid_pdf() {
        let result = extract_contract_text(b"not a pdf", "NATIVE_PDF");
        assert!(result.is_err());
    }

    #[test]
    fn test_extract_empty_pdf() {
        let result = extract_contract_text(b"", "NATIVE_PDF");
        assert!(result.is_err());
    }

    #[test]
    fn test_sha256_deterministic() {
        let data = b"test data";
        let hash1 = sha256_hex(data);
        let hash2 = sha256_hex(data);
        assert_eq!(hash1, hash2);
    }
}
