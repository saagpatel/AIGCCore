# Eval Gate Registry v3 (LOCKED)

Version: gates_registry_v3  
Status: LOCKED (stable IDs; do not rename or repurpose existing IDs)  
Purpose: Defines named evaluation gates that are executed by Core and recorded in `eval_report.json` (Evidence Bundle v1).

**Compatibility note:** All `*_V1` gate IDs are preserved exactly. This v2 document removes ambiguity (schemas, canonicalization reference, and conditional applicability) without changing the intent of existing IDs.

---

## Registry JSON (authoritative)
```json
{
  "registry_version": "gates_registry_v3",
  "gates": [
    {
      "gate_id": "BUNDLE_FORMAT.REQUIRED_FILES_V1",
      "category": "BUNDLE_FORMAT",
      "severity": "BLOCKER",
      "applies_to_policies": [
        "STRICT",
        "BALANCED",
        "DRAFT_ONLY"
      ],
      "pass_criteria": {
        "requires_files": [
          "BUNDLE_INFO.json",
          "run_manifest.json",
          "audit_log.ndjson",
          "eval_report.json",
          "artifact_hashes.csv",
          "inputs_snapshot/artifact_list.json",
          "inputs_snapshot/policy_snapshot.json",
          "inputs_snapshot/network_snapshot.json",
          "inputs_snapshot/model_snapshot.json",
          "exports/"
        ],
        "exports_layout": {
          "deliverables_dir_present": true,
          "attachments_dir_present": true,
          "templates_used_present": true
        },
        "optional_dirs": [
          "inputs_snapshot/artifacts/"
        ]
      },
      "evidence_required": [
        "<bundle_root>"
      ]
    },
    {
      "gate_id": "AUDIT_HASH_CHAIN.VERIFY_V1",
      "category": "AUDIT",
      "severity": "BLOCKER",
      "applies_to_policies": [
        "STRICT",
        "BALANCED",
        "DRAFT_ONLY"
      ],
      "pass_criteria": {
        "hash_algorithm": "SHA-256",
        "required_event_keys": [
          "ts_utc",
          "event_type",
          "run_id",
          "vault_id",
          "actor",
          "details",
          "prev_event_hash",
          "event_hash"
        ],
        "canonicalization": "PHASE_2_5_LOCK_ADDENDUM_V2_5_LOCK_4",
        "ndjson_chain_valid": true,
        "canonicalization_doc": "Phase_2_5_Lock_Addendum_v2.5-lock-4.md"
      },
      "evidence_required": [
        "audit_log.ndjson"
      ]
    },
    {
      "gate_id": "OFFLINE_ENFORCEMENT.MODE_PROOF_V1",
      "category": "OFFLINE_ENFORCEMENT",
      "severity": "BLOCKER",
      "applies_to_policies": [
        "STRICT",
        "BALANCED",
        "DRAFT_ONLY"
      ],
      "pass_criteria": {
        "requires_files": [
          "inputs_snapshot/network_snapshot.json",
          "audit_log.ndjson"
        ],
        "network_snapshot": {
          "network_mode_present": true,
          "proof_level_present": true,
          "ui_remote_fetch_disabled": true,
          "adapter_endpoints_present": true,
          "ui_remote_fetch_disabled_must_be_true": true,
          "adapter_endpoints_may_be_empty": true
        },
        "audit_events_required": [
          "NETWORK_MODE_SET",
          "ALLOWLIST_UPDATED"
        ]
      },
      "evidence_required": [
        "inputs_snapshot/network_snapshot.json",
        "audit_log.ndjson"
      ]
    },
    {
      "gate_id": "OFFLINE_ENFORCEMENT.ALLOWLIST_MATCH_V1",
      "category": "OFFLINE_ENFORCEMENT",
      "severity": "BLOCKER",
      "applies_to_policies": [
        "STRICT",
        "BALANCED"
      ],
      "pass_criteria": {
        "audit_events_required": [
          "ALLOWLIST_UPDATED"
        ],
        "egress_events": {
          "blocked_events_recorded": true,
          "allowed_events_reference_rule_id": true,
          "blocked_reasons_allowed": [
            "OFFLINE_MODE",
            "NOT_ALLOWLISTED",
            "UI_DIRECT_EGRESS_BLOCKED"
          ]
        }
      },
      "evidence_required": [
        "inputs_snapshot/network_snapshot.json",
        "audit_log.ndjson"
      ]
    },
    {
      "gate_id": "CITATIONS.STRICT_ENFORCED_V1",
      "category": "CITATIONS",
      "severity": "BLOCKER",
      "applies_to_policies": [
        "STRICT"
      ],
      "pass_criteria": {
        "citations_map_present": true,
        "citations_path_glob": "exports/**/attachments/citations_map.json",
        "every_claim_has_citation": true,
        "locators_valid": true,
        "artifact_refs_valid": true,
        "citations_schema_version": "LOCATOR_SCHEMA_V1",
        "claim_markers_required": true,
        "claim_marker_format": "<!-- CLAIM:C#### -->",
        "claims_missing_citations_must_be_zero": true
      },
      "evidence_required": [
        "exports/**/attachments/citations_map.json",
        "exports/**/deliverables/*.md",
        "artifact_hashes.csv"
      ]
    },
    {
      "gate_id": "REDACTION.REQUIRED_APPLIED_V1",
      "category": "REDACTION",
      "severity": "BLOCKER",
      "applies_to_policies": [
        "STRICT",
        "BALANCED"
      ],
      "pass_criteria": {
        "if_policy_requires_redaction": {
          "redactions_map_present": true,
          "redactions_path_glob": "exports/**/attachments/redactions_map.json",
          "required_redactions_applied": true,
          "redactions_schema_version": "REDACTION_SCHEMA_V1",
          "redaction_validation_must_pass": true,
          "required_redactions_definition": "Per Phase_2_5_Lock_Addendum_v2.5-lock-3 \u00a76.3 (restricted/tagged artifacts referenced by citations must be covered)."
        }
      },
      "evidence_required": [
        "exports/**/attachments/redactions_map.json",
        "exports/**/attachments/citations_map.json",
        "inputs_snapshot/artifact_list.json",
        "audit_log.ndjson"
      ]
    },
    {
      "gate_id": "MODEL_PINNING.MIN_LEVEL_V1",
      "category": "MODEL_PINNING",
      "severity": "BLOCKER",
      "applies_to_policies": [
        "STRICT",
        "BALANCED"
      ],
      "pass_criteria": {
        "when_model_unused_requires_null_snapshot_and_empty_calls_and_endpoints": true,
        "allowed_pinning_levels_by_policy": {
          "STRICT": [
            "CRYPTO_PINNED",
            "VERSION_PINNED"
          ],
          "BALANCED": [
            "VERSION_PINNED",
            "CRYPTO_PINNED"
          ],
          "DRAFT_ONLY": [
            "NAME_ONLY",
            "VERSION_PINNED",
            "CRYPTO_PINNED"
          ]
        }
      },
      "evidence_required": [
        "inputs_snapshot/model_snapshot.json"
      ]
    },
    {
      "gate_id": "VAULT_CRYPTO.ENCRYPTION_AT_REST_V1",
      "category": "VAULT_CRYPTO",
      "severity": "BLOCKER",
      "applies_to_policies": [
        "STRICT",
        "BALANCED",
        "DRAFT_ONLY"
      ],
      "pass_criteria": {
        "snapshot_evidence_consistent": true,
        "when_encryption_at_rest_true_requires_matching_vault_event": true,
        "vault_crypto_algorithms_allowed": [
          "XCHACHA20_POLY1305",
          "AES_256_GCM"
        ]
      },
      "evidence_required": [
        "inputs_snapshot/policy_snapshot.json",
        "audit_log.ndjson"
      ]
    },
    {
      "gate_id": "DETERMINISM.ZIP_PACKAGING_V1",
      "category": "DETERMINISM",
      "severity": "BLOCKER",
      "applies_to_policies": [
        "STRICT",
        "BALANCED"
      ],
      "pass_criteria": {
        "when_determinism_enabled": {
          "zip_sort_order": "LEX_PATH",
          "zip_mtime": 0,
          "compression_fixed": true,
          "zip_compression_method": "DEFLATE",
          "zip_compression_level": 9
        }
      },
      "evidence_required": [
        "<bundle_zip_bytes>",
        "run_manifest.json"
      ]
    },
    {
      "gate_id": "DETERMINISM.PDF_CAPABLE_V1",
      "category": "DETERMINISM",
      "severity": "MAJOR",
      "applies_to_policies": [
        "STRICT",
        "BALANCED"
      ],
      "pass_criteria": {
        "when_pdf_determinism_enabled": {
          "pdf_metadata_fixed": true,
          "pdf_ids_derived_from_run_id": true,
          "fonts_pinned": true,
          "if_no_pdfs": "NOT_APPLICABLE",
          "if_all_pdfs_pdf_determinism_disabled": "NOT_APPLICABLE"
        }
      },
      "evidence_required": [
        "exports/**/deliverables/*.pdf",
        "run_manifest.json"
      ]
    }
  ],
  "generated_at_ms": 0
}
```

End.
