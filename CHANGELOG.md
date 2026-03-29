# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-03-24

### Added
- Close out phases 4 and 5 hardening
- Begin phase 4–7 implementation scaffolding
- HealthcareOS Pack: clinical documentation workflow with consent validation
- FinanceOS Pack: financial analysis, exception detection, dual-template reporting
- IncidentOS Pack: log analysis, timeline reconstruction, dual-template rendering
- RedlineOS Pack: extraction, segmentation, risk assessment, and rendering
- EvidenceOS: complete phase 3 pack implementation
- Core: implement phase 2 governance baseline
- Codex reliability gate workflow
- CodeQL analysis workflow configuration
- Comprehensive review and validation report for all phases

### Fixed
- Restore Windows icon packaging and closeout evidence
- Remove duplicate TruffleHog fail flag
- Avoid Unix checksum self-hash artifact
- Prevent Windows checksum self-hash file lock
- Include Windows ico in Tauri bundle icons
- Resolve policy diff base for main/master repos
- Add Windows icon resource and unblock Windows and Linux release gates
- Correct release metadata parsing delimiter
- Address EvidenceOS phase 3 follow-up risks
- Use a valid Trivy action tag and repair Codex security workflow

### Changed
- Align agent communication contract labels
- Capture glib remediation execution blocker
- Close phase 5 follow-up artifacts and remaining phase completion items
- Refresh v0.1.0 evidence packet
- Make CodeQL advanced workflow manual-only
- Phase 5 closeout and evidence sync
- Harden phase 3 artifact contract
- Bootstrap tests and docs defaults
- Prune legacy docs and fix Tauri redline export
- Bump flatted dependency
