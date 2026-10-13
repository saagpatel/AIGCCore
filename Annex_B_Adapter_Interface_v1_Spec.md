# Annex B — Adapter Interface v1 Specification (Locked)

**Document status:** Normative current adapter contract.

**Status:** Locked v1.0.0  
**Purpose:** Standardize local-only integration with model runtimes (LLM/VLM/STT/Embeddings) without coupling pack logic to any single runtime.

---

## B.1 Transport

- Local HTTP on `127.0.0.1` only.
- Adapters MUST NOT bind to external interfaces.
- Core treats adapter endpoints as local-only resources; any external egress is governed by the core network boundary.

---

## B.2 Common endpoints

### `GET /v1/health`

Returns: `{ status, adapter_id, adapter_version, uptime_ms }`

### `GET /v1/capabilities`

Returns:

- `adapter_type`: LLM|VLM|STT|EMB
- `features`: e.g., json_schema, streaming, timestamps
- `limits`: max_input_bytes, max_batch, max_context_tokens
- `models[]`: { model_id, model_sha256?, quantization?, context_window?, notes? }

### `POST /v1/models/resolve`

Input: preferred model + constraints  
Output: resolved model + rationale

### Error envelope (all endpoints)

`{ error: { code, message, retryable, category, details } }`

Categories: INVALID_INPUT, MODEL_NOT_FOUND, OUT_OF_MEMORY, TIMEOUT, RUNTIME_ERROR, SAFETY_REFUSAL, NOT_SUPPORTED

---

## B.3 LLM adapter

### `POST /v1/llm/generate`

Inputs:

- call_id, model_id, messages[]
- response_mode: TEXT|JSON
- json_schema (required if JSON)
- temperature, top_p, max_tokens, seed (best-effort)
- context_chunks[] (for retrieval + citation support)
- safety_profile: require_citations, forbid_untrusted_tool_use, redaction_required

Outputs:

- output_text or output_json
- usage (tokens_in/out), timing_ms
- output_hash, determinism status
- status: ok|refused|error

---

## B.4 Embeddings adapter

### `POST /v1/emb/embed`

Inputs: call_id, model_id, texts[], normalize  
Outputs: vectors, dim, output_hash

---

## B.5 STT adapter

### `POST /v1/stt/transcribe`

Inputs: call_id, model_id, audio_uri, language?, timestamps, diarization  
Outputs: segments[{ start_ms, end_ms, speaker?, text, confidence? }], full_text, output_hash

---

## B.6 VLM adapter

### `POST /v1/vlm/analyze`

Inputs:

- frames[{ artifact_id, page_index, image_uri }]
- task: OCR|STRUCTURE|QA
- prompt (for QA/structure)
  Outputs:
- blocks[{ page_index, bbox, text, confidence }]
- answer? (for QA)
- output_hash

---

## B.7 Logging requirements

Adapters MUST return metadata required for audit:

- call_id, model_id, adapter_version
- durations, usage counts
- input/output hashes (or sufficient metadata for the core to compute)

Core logs:

- MODEL_CALL_STARTED (input_hash)
- MODEL_CALL_COMPLETED (output_hash + usage + status)
- MODEL_CALL_FAILED (error envelope)
