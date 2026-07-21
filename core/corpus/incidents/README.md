# IncidentOS Corpus - Regression Testing Guide

## Purpose

The incident corpus provides golden outputs for regression testing Phase 5 (IncidentOS) across different platforms (macOS, Windows, Linux). This ensures deterministic behavior: same incident log always produces identical timeline, customer packet, and internal packet outputs.

## Structure

```
incidents/
├── README.md (this file)
├── sample_incident.ndjson
└── expected_outputs/
    ├── sample_incident_customer_packet.md
    └── sample_incident_internal_packet.md
```

## Sample Data

**sample_incident.ndjson**: 8-event incident timeline covering:
- System startup
- User authentication
- Database queries
- Firewall alerts
- Intrusion detection trigger
- Incident creation
- Access violations
- Forensic analysis

Severity distribution:
- 2 HIGH: breach attempt, unauthorized access
- 1 MEDIUM: firewall alert
- 5 LOW: normal operations

## Expected Outputs

### Customer Packet (Redacted)
- Path: `expected_outputs/sample_incident_customer_packet.md`
- Profile: BASIC (PII redaction only)
- Citations: `<!-- CLAIM:C... -->` markers present for each event
- Sensitive data: Email addresses and IP addresses redacted with `[REDACTED: ...]`

### Internal Packet (Unredacted)
- Path: `expected_outputs/sample_incident_internal_packet.md` (not yet created)
- Profile: None (full details)
- Citations: `<!-- CLAIM:C... -->` markers present
- Sensitive data: All details visible

### Timeline CSV
- Deterministic event ordering by timestamp
- CSV columns: timestamp, system, actor, action, resource, severity, anchor_id

## Regression Testing Process

### One-Time Setup (When Adding New Corpus Items)

1. Prepare incident log (NDJSON or JSON)
2. Execute Phase 5 workflow on sample log:
   ```bash
   cargo test --lib incidentos::workflow::integration_tests 2>&1 | grep PASS
   ```
3. Run workflow manually to generate outputs:
   ```rust
   let input = IncidentOsInputV1 { ... };
   let output = execute_incidentos_workflow(input, log_content)?;
   // Save outputs to expected_outputs/
   ```
4. Commit golden outputs to corpus

### Continuous Regression Testing

**Gate: `INCIDENTOS.DETERMINISM_V1` (BLOCKER severity)**

Run on every CI/CD pipeline:

```bash
pnpm gate:all
```

The gate:
1. Loads golden outputs from `expected_outputs/`
2. Re-runs workflow on `sample_incident.ndjson`
3. Compares hashes of:
   - customer_packet.md
   - internal_packet.md
   - timeline.csv
4. **FAILS if any hash differs** (determinism violation)
5. **SKIPS if expected_outputs/ not present** (corpus incomplete)

## Platform Parity Validation

The gate is BLOCKER severity, meaning:
- Phase 5 cannot ship to production if determinism fails
- Same incident log must produce **byte-identical** outputs on all platforms
- Prevents silent non-determinism bugs (e.g., timestamp parsing, sorting differences)

## Maintenance

### Adding New Test Scenarios

1. Create new incident log: `incidents/scenario_name.ndjson`
2. Run workflow: capture customer_packet.md, internal_packet.md, timeline.csv
3. Move outputs to: `incidents/expected_outputs/scenario_name_*.md`
4. Commit together with gate update if new scenario requires new gate

### Updating Golden Outputs

**Only do this when:**
- Feature changes require new output format
- Bug fix changes determinism behavior (log this in commit message)
- **Never** manually edit golden outputs; always regenerate from workflow

**Process:**
1. Fix code / implement feature
2. Run Phase 5 workflow
3. Capture actual output
4. Verify output is correct
5. Replace expected_outputs file
6. Commit with clear message: "Update corpus: <reason>"

## Known Issues

- MVP corpus has 1 incident log (8 events); real regression testing needs 10+ diverse scenarios
- Golden outputs generated on 2026-02-12; future updates required if redaction rules change
- Corpus doesn't cover edge cases: malformed JSON, missing timestamps, duplicate events

## Next Steps

### Phase 5 Completion
- Gate implementation: `tools/gates/check-incidentos-determinism.mjs`
- Tauri handler: `src-tauri/src/lib.rs` run_incidentos command
- UI panel: `src/ui/packs/IncidentOSPanel.tsx`

### Future Enhancement
- Add 10+ incident scenarios with different:
  - Severity profiles (all HIGH, mixed, all LOW)
  - Timeline lengths (3 events to 1000 events)
  - Redaction profiles (BASIC, STANDARD, STRICT all tested)
  - Data formats (JSON, NDJSON, CSV variations)
