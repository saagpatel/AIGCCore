use crate::error::{CoreError, CoreResult};
use crate::redlineos::model::{SegmentedClause, ClauseAnchor};
use regex::Regex;
use sha2::{Sha256, Digest};

/// Segment extracted contract text into clauses
///
/// Uses heuristic-based segmentation:
/// - Numbered clauses (1.1, 1.2, 2.0, etc.)
/// - Headings
/// - Section breaks
pub fn segment_clauses(
    extracted_text: &str,
    contract_id: &str,
) -> CoreResult<Vec<SegmentedClause>> {
    if extracted_text.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut clauses = Vec::new();

    // Pattern for numbered clauses (e.g., "1.1", "2.0", "1.2.3")
    let clause_pattern = Regex::new(r"(?m)^(\d+(?:\.\d+)*)\s+([^\n]+)")
        .map_err(|_e| CoreError::InvalidInput("Regex compilation failed".to_string()))?;

    let mut clause_idx = 0;
    let matches: Vec<_> = clause_pattern.find_iter(extracted_text).collect();

    for (i, mat) in matches.iter().enumerate() {
        let clause_start = mat.start();

        // Find next clause or end of text
        let clause_end = if i + 1 < matches.len() {
            matches[i + 1].start()
        } else {
            extracted_text.len()
        };

        let clause_text = extracted_text[clause_start..clause_end].trim();

        if !clause_text.is_empty() {
            let clause = create_clause(
                clause_text,
                contract_id,
                clause_idx,
                clause_start,
            );
            clauses.push(clause);
            clause_idx += 1;
        }
    }

    // If no numbered clauses found, treat entire text as one clause
    if clauses.is_empty() {
        clauses.push(SegmentedClause {
            clause_id: format!("{}_C0", contract_id),
            clause_number: Some("1.0".to_string()),
            title: Some("General Terms".to_string()),
            text: extracted_text.to_string(),
            start_page: 0,
            start_char_offset: 0,
            end_char_offset: extracted_text.len(),
            confidence: 0.7,
        });
    }

    Ok(clauses)
}

/// Create a single segmented clause
fn create_clause(
    text: &str,
    contract_id: &str,
    clause_idx: usize,
    start_offset: usize,
) -> SegmentedClause {
    let trimmed_text = text.trim().to_string();
    let text_len = trimmed_text.len();

    SegmentedClause {
        clause_id: format!("{}_C{}", contract_id, clause_idx),
        clause_number: Some(format!("{}.0", clause_idx + 1)),
        title: None,
        text: trimmed_text,
        start_page: 0,
        start_char_offset: start_offset,
        end_char_offset: start_offset + text_len,
        confidence: 0.85,
    }
}

/// Generate deterministic anchors for clauses
///
/// Anchor format: REDLINE_<contract_id>_<text_hash_truncated>_<offset>
pub fn generate_anchors(
    clauses: &[SegmentedClause],
    contract_id: &str,
) -> CoreResult<Vec<ClauseAnchor>> {
    let mut anchors = Vec::new();

    for clause in clauses {
        let text_hash = sha256_hex(clause.text.as_bytes());

        let anchor_id = format!(
            "REDLINE_{}_{}_{}",
            contract_id,
            &text_hash[..8],
            clause.start_char_offset,
        );

        anchors.push(ClauseAnchor {
            anchor_id,
            clause_id: clause.clause_id.clone(),
            text_hash,
            page_hint: Some(clause.start_page),
            char_offset_range: (clause.start_char_offset, clause.end_char_offset),
        });
    }

    Ok(anchors)
}

/// Stable clause anchor (legacy function kept for compatibility)
pub fn stable_clause_anchor(clause_text: &str) -> String {
    let normalized = clause_text.split_whitespace().collect::<Vec<_>>().join(" ");
    let digest = sha256_hex(normalized.as_bytes());
    format!("clause_{}", &digest[..16])
}

/// SHA-256 hash of bytes as hex string (deterministic)
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_segment_empty_text() {
        let clauses = segment_clauses("", "contract_1").unwrap();
        assert_eq!(clauses.len(), 0);
    }

    #[test]
    fn test_anchor_determinism() {
        let clause = SegmentedClause {
            clause_id: "c1_C0".to_string(),
            clause_number: None,
            title: None,
            text: "Test clause text".to_string(),
            start_page: 0,
            start_char_offset: 0,
            end_char_offset: 16,
            confidence: 0.9,
        };

        let anchors1 = generate_anchors(&[clause.clone()], "c1").unwrap();
        let anchors2 = generate_anchors(&[clause], "c1").unwrap();

        assert_eq!(anchors1[0].anchor_id, anchors2[0].anchor_id);
    }

    #[test]
    fn test_sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn test_anchor_id_uses_canonical_sha256_prefix() {
        let clause = SegmentedClause {
            clause_id: "c1_C0".to_string(),
            clause_number: None,
            title: None,
            text: "Test clause text".to_string(),
            start_page: 0,
            start_char_offset: 0,
            end_char_offset: 16,
            confidence: 0.9,
        };

        let anchors = generate_anchors(&[clause], "c1").unwrap();

        assert_eq!(anchors[0].anchor_id, "REDLINE_c1_bb94b4ff_0");
        assert_eq!(
            anchors[0].text_hash,
            "bb94b4ffb11901e8ebf51dbf5cec68abf6b355fc4d2ae64e4ffed0d80808a919"
        );
    }

    #[test]
    fn test_stable_clause_anchor_normalizes_whitespace() {
        assert_eq!(
            stable_clause_anchor(" Spaced   clause\ntext "),
            "clause_90d06d3830ba1f5b"
        );
    }
}
