# enc2sop Product Launch Roadmap

Date: `2026-05-25`
Purpose: align future Codex/GPT-5.5 iterations around broad product launch readiness, not only CI promotion evidence.

## 1. Product Launch Tracks

`enc2sop` now has three distinct launch tracks.

| Track | Scope | Current Judgment | Required Gate |
| --- | --- | --- | --- |
| Mainline Beta | `protect -> build -> package -> verify -> release` | close to external Beta once live promotion execution evidence is archived | `ENC-P0-016` |
| Beta With Airgap | mainline plus `soenc transport` QR/OCR transfer | generated-page sidecar certification, production profile, basic distortion suite, and synthetic stress distortion suite pass; still missing real camera/photo, full print-scan, and generic OCR-only certification | `ENC-P0-019` |
| GA Platform | mainline plus documented operational rollout and certified optional transport profile | not ready until Beta evidence and reliability data exist | live CI evidence plus transport reliability reports |

## 2. Current Transport/OCR Judgment

The OCR/cross-medium transfer problem is not proven "completely solved".

What is already implemented:

- transport is optional and does not block the mainline protection flow
- auto recovery prefers sidecar geometric decode before OCR
- manifest-guided structured extraction exists before generic OCR fallback
- external OCR provider integration exists
- generic OCR fallback exists through optional `tesseract` and `easyocr`
- line CRC, page CRC, compressed SHA256, raw SHA256, and manifest validation exist
- chunk duplication, parity-group recovery, missing-chunk diagnostics, and retake plans exist
- focused transport tests pass for current protocol/sidecar/recovery behavior
- `soenc transport certify` can generate `enc2sop-transport-reliability-report/v1` for deterministic generated-page sidecar recovery
- `reliable-airgap-v1` production profile fails closed on unsafe sidecar/CRC/metadata/redundancy settings
- `generated-page-basic-v1` distortion certification covers generated-page control, PNG re-encode, JPEG recompression, mild blur, mild contrast/brightness shift, and screenshot-like high-quality recompression
- `generated-page-stress-v1` now certifies generated-page sidecar recovery for resize down/up, small rotation, crop/margin loss, deterministic skew approximation, sparse noise, and print-scan-like grayscale/contrast/blur approximation
- operator-supplied capture corpus ingestion now exists for `soenc transport certify` through schema `enc2sop-transport-capture-corpus/v1`; reports bind case labels, source/attached image SHA256 values, optional capture metadata, backend, success/failure reason, and corpus classification (`real`, `lab`, `synthetic`, or `stress-only`)
- `soenc transport prepare-capture-corpus` can stage a replayable physical/lab capture kit with generated pages, empty capture drop directories, `capture_corpus.json`, `capture_kit_manifest.json` (`enc2sop-transport-capture-kit/v1`), and operator next-step instructions
- `soenc transport prepare-capture-corpus --include-raw-capture-dirs` can stage real camera perspective-correction kits with `captures/*__raw` raw-photo directories, per-case `raw_image_paths`, and `perspective_correction` metadata so raw/corrected camera artifacts can be attached without hand-editing the corpus
- `soenc transport prepare-capture-corpus --ocr-only-backend {tesseract,easyocr,external}` can stage a sidecar-free OCR-only capture kit under non-production profile `ocr-only-backend-v1`; the corpus and kit manifest record the named backend, generated manifests now explicitly record `sidecar_enabled=false`, and instructions tell operators to certify with `--require-ocr-only-backend`
- `soenc transport ingest-capture-corpus` can map externally returned lab/real photo or scan folder trees into a prepared `capture_corpus.json` without hand-editing; it writes `enc2sop-transport-capture-corpus-ingestion-report/v1`, records case labels, source image SHA256/size values, optional raw-photo roots, capture metadata, classification, medium, and kit-manifest summary updates, while remaining ingestion evidence only
- `soenc transport attach-capture-corpus` can refresh a prepared capture corpus after operator photos/scans are dropped into `captures/*`; it writes `transport_capture_attachment_report.json` (`enc2sop-transport-capture-attachment-report/v1`), records attached image SHA256 values in `capture_corpus.json`, and updates the capture kit summary without claiming recovery certification
- `soenc transport attach-capture-corpus --require-raw-captures` fails closed with `raw_capture_images_missing` until every staged camera case has raw-photo images attached under `raw_image_paths`
- `soenc transport correct-capture-perspective` can materialize corrected camera recovery images from staged `raw_image_paths`, record raw/corrected/reference SHA256 bindings in `enc2sop-transport-capture-perspective-correction-report/v1`, and update the capture corpus `image_path` before attachment/certification; this is preparation evidence only and does not certify real camera transfer without the existing real-camera certification/archive/status gates
- `soenc transport validate-capture-corpus` writes `enc2sop-transport-capture-corpus-validation/v1`, a pre-certification readiness report that checks corpus structure, profile compliance, attached capture/raw/reference image SHA256s, distinctness from generated references, attachment-report lineage, and optional physical print-scan, real-camera perspective, or OCR-only backend gates without running recovery or certifying a medium
- `soenc transport certify --require-capture-attachment-report` can bind certification to `transport_capture_attachment_report.json`; it fails closed with `capture_attachment_report_mismatch` unless the current capture, raw-photo, and reference image SHA256/size/path records match the attachment report, proving the measurement used the same attached files without certifying a medium by itself
- `soenc transport certify`, `validate-capture-corpus`, and `certify-capture-evidence` now support `--require-capture-provenance`; this non-default gate fails closed with `capture_provenance_missing` unless lab/real capture cases declare a capture medium and record session, operator, timestamp, and capture-device metadata such as `capture_session_id`, `operator`, `captured_at_utc`, and scanner/camera/printer identity
- `soenc transport archive-evidence` packages a measured `transport_reliability_report.json`, capture corpus, attachment report, and referenced payload/manifest/capture/raw/reference/recovery artifacts into `transport_capture_evidence_archive.zip` with a versioned manifest schema `enc2sop-transport-capture-evidence-archive/v1`; archive creation can now fail closed on the exact claim gate being packaged (`--require-profile-certified`, `--require-physical-print-scan`, `--require-real-camera-perspective-correction`, or `--require-ocr-only-backend`), preserving replayability without broadening the certification claim beyond the included report gates
- `soenc transport verify-evidence-archive` verifies a transport evidence ZIP before replay/audit use; it checks the embedded/external archive manifests, safe ZIP member paths, exact member inventory, per-file SHA256/size, archived report/corpus/attachment schemas, and optional gate requirements without broadening the certification claim
- `soenc transport replay-evidence-archive` now writes `enc2sop-transport-capture-evidence-archive-replay/v1`; it verifies the evidence ZIP, extracts archived bytes, rewrites archived corpus/attachment paths to extracted files, reruns recovery for the archived capture corpus, and compares replayed case outcomes to the archived measured report without broadening the certification claim
- `soenc transport certify-capture-evidence` orchestrates the operator-capture evidence chain in one command: optional external capture-folder ingestion (`--capture-root` / `--raw-capture-root`), attach, validate, certify, archive, verify, executable archive replay, and certification status. It writes `enc2sop-transport-capture-certification-pipeline/v1`, records whether ingestion was used, and fails closed before attachment/certification when ingestion misses required captures or before status if archive replay diverges; the pipeline does not broaden any claim beyond the measured report and requested certification gates
- `transport_reliability_report.json`, archive manifests, and archive verification reports now carry machine-readable `certification_claims` (`enc2sop-transport-certification-claims/v1`) so launch/audit tooling can distinguish generated-page sidecar certification, generated-page synthetic stress certification, lab/real physical print-scan certification, real camera perspective-correction certification, backend-specific OCR-only measurement, and still-uncertified modes without inferring from scattered fields
- `soenc transport certification-status` now writes `enc2sop-transport-certification-status/v1`, a product-facing matrix derived from a measured report, a verification report, or a freshly verified evidence archive; it records source SHA256, profile state, certified/uncertified claims, evidence level, missing gates, recommended next evidence steps, and optional `--require-certified-claim` fail-closed gates without broadening the underlying `certification_claims`
- capture corpus certification now supports explicit physical/lab evidence gates: `--capture-required-classification`, `--capture-required-success-rate`, and `--require-distinct-capture-images`; prepared kits bind generated reference page paths so byte-identical fixture copies fail closed instead of counting as scanner/camera evidence
- real camera perspective-correction certification now has an explicit non-default evidence gate: `--require-real-camera-perspective-correction`; capture cases must be classified `real`, include raw camera `raw_image_paths`, include corrected recovery images in `image_path`, bind generated `reference_image_paths`, declare `perspective_correction.applied=true` plus a method, and prove raw/corrected/reference image sets are byte-distinct
- physical print-scan certification now has an explicit non-default evidence gate: `--require-physical-print-scan`; capture cases must be classified `lab` or `real`, declare `capture_medium=print-scan`, include generated `reference_image_paths`, include byte-distinct scanned recovery images in `image_path`, and record printer/scanner/dpi metadata before any physical print-scan claim can be made
- backend-specific OCR-only certification now has an explicit non-default evidence gate: `--require-ocr-only-backend`; runs must use `tesseract`, `easyocr`, or `external`, must use sidecar-free pages, record per-case `ocr_only_evidence`, record per-backend thresholds, and fail closed with `ocr_only_evidence_missing` if a binary sidecar is present or the selected OCR backend does not match the requested backend

What is missing:

- no production-certified real-world corpus has been archived yet for camera/photo capture, full print-scan degradation, real camera perspective correction, and generic OCR fallback
- no archived real camera/photo transfer, physical print-scan, or real backend-specific OCR-only report has passed a measured threshold yet
- no product-wide GA launch statement has been made for optional transport; report-level `certification_claims` and derived `certification-status` artifacts now separate sidecar-certified transfer from best-effort or backend-specific OCR evidence, but real GA claims still require archived measured reports for the claimed medium/backend

## 3. Release Policy

Mainline product launch must not be blocked by optional transport/OCR work when transport remains documented as optional or experimental.

Transport/OCR must block launch only when the launch claim includes one of these promises:

- "airgap transfer is Beta-ready"
- "QR/OCR transfer is production-ready"
- "cross-medium OCR transfer is a reliable product capability"
- "GA platform includes certified transport reliability"

Until `ENC-P0-019` is complete, product copy and operator docs must phrase real camera/photo, real print-scan, and generic OCR transport as optional and not GA-certified. The generated-page sidecar path may be described as locally certifiable only when a fresh `transport_reliability_report.json` is produced by `soenc transport certify --profile reliable-airgap-v1`. The generated-page synthetic stress path may be described only when the report also uses `--distortion-suite generated-page-stress-v1` and passes all per-distortion gates.

Before any external transport claim is used in launch copy, generate `soenc transport certification-status` from the measured report or verified archive and quote only claims whose row has `certified=true`. For release checklists or launch automation, add `--require-certified-claim <claim>` for each claim the copy depends on; the status artifact then writes `claim_gate` metadata and exits non-zero if any requested claim is still uncertified.

## 4. Required New Evidence

Transport reliability work must produce:

- `transport_reliability_report.json`
- deterministic payload corpus metadata
- distortion-suite configuration
- per-backend recovery statistics
- success/failure reason counts
- missing-chunk and parity-recovery statistics
- runtime/throughput statistics
- artifact SHA256 bindings for rendered pages, recovered payloads, and generated reports

## 5. Acceptance Thresholds

Initial thresholds for the next implementation pass:

| Capability | Required For | Threshold |
| --- | --- | --- |
| sidecar decode from tool-generated digital PNG pages | Beta With Airgap | 100% recovery |
| manifest-guided sidecar decode without OCR runtime | Beta With Airgap | 100% recovery for generated pages |
| manifest-guided structured OCR on clean screenshots | Beta With Airgap candidate | >= 99% recovery after calibrated harness data |
| external OCR provider mode | integration readiness | deterministic contract tests plus provider-specific report |
| generic OCR fallback | GA claim only if certified | best-effort unless measured threshold is met |
| OCR-only transfer without sidecar/redundancy | never default production path | must require explicit opt-in and warning/fail-closed profile behavior |

These thresholds may be adjusted only after a checked-in report shows measured data and the task cards are updated.

## 6. Construction Plan

### `ENC-P0-017` Transport Reliability Certification Harness

Build a repeatable harness that generates payloads, exports transport pages, applies deterministic distortion suites, attempts recovery, and writes `transport_reliability_report.json`.

Status: first vertical slice delivered on 2026-05-25.

Minimum vertical slice:

- digital generated pages
- sidecar backend
- random payload corpus across small and medium sizes
- report schema with success rate, backend, payload size, chunk count, parity settings, and failure reasons

Delivered behavior:

- `soenc transport certify`
- schema `enc2sop-transport-reliability-report/v1`
- deterministic payload corpus via `--payload-size`, `--iterations-per-size`, and `--seed`
- digital PNG export plus manifest-guided sidecar recovery
- per-case SHA256 bindings for payload, manifest, rendered images, and restored output
- per-case page/chunk/redundancy/parity/runtime/recovery metric records
- fail-closed non-zero CLI exit when required success-rate threshold is not met

Local evidence generated during implementation:

- `.tmp_transport_certification_20260525/transport_reliability_report.json`
- parameters: payload sizes `64` and `257`, seed `20260525`, backend `sidecar`, redundancy copies `2`, parity group size `4`
- result: `2/2` passed, success rate `1.0`, failure reasons `{}`

### `ENC-P0-018` Reliable Airgap Production Profile

Add a production profile for airgap transfer, for example `reliable-airgap-v1`.

Status: delivered on 2026-05-25.

Minimum behavior:

- sidecar required by default
- manifest required by default
- line CRC and page CRC required
- SHA256 verification required
- parity or redundancy required above a size threshold
- generic OCR fallback disabled unless explicitly allowed
- CLI warnings become fail-closed errors under the production profile

Delivered behavior:

- `--profile reliable-airgap-v1`
- profile compliance block in `transport_reliability_report.json`
- fail-closed rejection for no sidecar, disabled line CRC, missing page/hash metadata, disabled manifest-guided line indexing, and no redundancy/parity above threshold
- explicit `--allow-ocr-fallback` and `--allow-unsafe-profile` flags for experimental runs that should not be treated as production-certified
- report field `profile_certified` separates executable evidence from production-certified evidence

Local evidence generated during implementation:

- `.tmp_transport_reliable_profile_20260525/transport_reliability_report.json`
- parameters: profile `reliable-airgap-v1`, payload sizes `64` and `257`, seed `20260525`, backend `sidecar`, redundancy copies `2`, parity group size `4`
- result: `2/2` passed, success rate `1.0`, `profile_certified=true`

### `ENC-P0-019` Distortion Corpus And Certification Gate

Expand the harness to realistic transfer degradation.

Status: in progress; generated-page basic and synthetic stress distortion slices delivered on 2026-05-25.

Delivered behavior:

- `--distortion-suite generated-page-basic-v1`
- `--distortion-suite generated-page-stress-v1`
- per-case distortion metadata and distorted image SHA256/size bindings
- per-distortion success rates, failure reasons, and threshold gates in `transport_reliability_report.json`
- first basic suite covers control, PNG re-encode, JPEG quality 95, mild blur, mild contrast/brightness, and screenshot-like high-quality recompression
- stress suite covers resize down/up, small rotation, crop/margin loss, deterministic skew approximation, sparse noise, and print-scan-like grayscale/contrast/blur approximation

Local evidence generated during implementation:

- `.tmp_transport_distortion_basic_20260525/transport_reliability_report.json`
- parameters: profile `reliable-airgap-v1`, distortion suite `generated-page-basic-v1`, payload sizes `64` and `257`, seed `20260525`, backend `sidecar`, redundancy copies `2`, parity group size `4`
- result: `12/12` passed, success rate `1.0`, each basic distortion success rate `1.0`, `profile_certified=true`
- `.tmp_transport_distortion_stress_iter157e/transport_reliability_report.json`
- parameters: profile `reliable-airgap-v1`, distortion suite `generated-page-stress-v1`, payload size `64`, seed `20260525`, backend `sidecar`, redundancy copies `2`, parity group size `4`
- result: `13/13` passed, success rate `1.0`, every synthetic stress distortion success rate `1.0`, `profile_certified=true`
- operator capture corpus contract evidence:
  - schema: `enc2sop-transport-capture-corpus/v1`
  - CLI flags: `--capture-corpus-file` and `--capture-corpus-only`
  - report fields: `capture_corpus`, per-case `capture_corpus`, `artifact_digests.source_images`, capture classification counts, profile-certified counts, and per-classification success rates
  - fail-closed behavior: under `reliable-airgap-v1`, attached capture cases fail with `capture_profile_not_certified` if manifest sidecar layout, line CRC, compact page/hash metadata, manifest-guided line indexing, payload SHA256 binding, or redundancy/parity proof is weakened
  - local unit evidence uses a generated lab fixture only; it proves the attachment contract, not real-world camera or physical print-scan readiness
- physical/lab capture kit preparation evidence:
  - schema: `enc2sop-transport-capture-kit/v1`
  - CLI command: `soenc transport prepare-capture-corpus`
  - staged artifacts: deterministic payloads, generated source pages, empty operator capture directories, `capture_corpus.json`, `capture_kit_manifest.json`, and `instructions/NEXT_STEPS.md`
  - certification boundary: a kit and attachment report are not transport recovery evidence by themselves; real photos/scans must be placed into `captures/*`, bound with `soenc transport attach-capture-corpus`, and then measured with `soenc transport certify --capture-corpus-file ... --capture-corpus-only`
  - strict physical/lab evidence gates:
    - prepared corpus cases include `reference_image_paths` for generated source pages
    - `--require-distinct-capture-images` fails closed when attached capture images are byte-identical to generated references
    - `--capture-required-classification` requires an explicit `real`, `lab`, `synthetic`, or `stress-only` case to be present
    - `--capture-required-success-rate` applies a per-classification threshold gate
    - `--require-real-camera-perspective-correction` requires real camera raw photos, corrected recovery images, declared perspective-correction metadata, and byte-distinct raw/corrected/reference image sets before camera perspective-correction support can be claimed
    - `--require-physical-print-scan` requires lab/real print-scan cases with `capture_medium=print-scan`, printer/scanner/dpi metadata, reference pages, and byte-distinct scanned images before physical print-scan support can be claimed
    - `--require-ocr-only-backend` requires `tesseract`, `easyocr`, or `external` backend evidence on sidecar-free pages before any OCR-only backend claim can be made
  - local contract evidence: `.tmp_transport_capture_kit_20260526/capture_kit_manifest.json`, `.tmp_transport_capture_kit_20260526/capture_corpus.json`, and `.tmp_transport_capture_kit_20260526/cert/transport_reliability_report.json`
  - result: kit staging produced `2` lab cases and `8` generated page images; controlled fixture certification passed `2/2` at success rate `1.0` after copying generated pages into the capture directories
  - note: this is still not real camera/photo or physical print-scan certification
  - capture attachment contract evidence:
    - CLI command: `soenc transport attach-capture-corpus`
    - schema: `enc2sop-transport-capture-attachment-report/v1`
    - report fields: per-case attached image SHA256/size records, reference-image SHA256 records, raw-image SHA256 records when provided, capture classification/medium counts, byte-identical reference-match counts, raw-capture presence counts, and updated-file list
    - local evidence: `.tmp_transport_capture_attach_20260526/capture_kit_manifest.json`, `.tmp_transport_capture_attach_20260526/capture_corpus.json`, and `.tmp_transport_capture_attach_20260526/attach/transport_capture_attachment_report.json`
    - parameters: classification `lab`, capture medium `print-scan`, payload size `64`, seed `20260526`, `--require-captures`, `--require-distinct-capture-images`
    - result: one intentionally modified fixture image was attached and hash-bound successfully; this proves the attachment workflow and distinct-file gate only, not real scanner/camera recovery evidence
  - attachment-report certification lineage gate:
    - CLI flags: `--capture-attachment-report-file` and `--require-capture-attachment-report`
    - reports include per-case `capture_corpus.attachment_report_evidence`, report SHA256 binding, current-vs-reported image comparisons, summary `capture_attachment_report_evidence_counts`, and thresholds `capture_attachment_report_required` / `capture_attachment_report_passed`
    - local evidence: `.tmp_transport_attachment_lineage_20260527/capture_corpus.json`, `.tmp_transport_attachment_lineage_20260527/attach/transport_capture_attachment_report.json`, and `.tmp_transport_attachment_lineage_20260527/cert/transport_reliability_report.json`
    - result: fixture-based lab attachment succeeded and certification passed only when the attached image matched the attachment report; a drifted capture failed closed with `capture_attachment_report_mismatch`
    - note: this proves replayable file-lineage binding only; it is still not real camera/photo or physical print-scan certification
  - capture corpus validation preflight:
    - CLI command: `soenc transport validate-capture-corpus`
    - schema: `enc2sop-transport-capture-corpus-validation/v1`
    - report fields: per-case profile compliance, attached/reference/raw image SHA256 records, distinct-reference status, attachment-report evidence, physical print-scan evidence, real-camera perspective-correction evidence, readiness counts, and failures by reason
    - local evidence: `.tmp_transport_capture_validation_20260527/capture_kit_manifest.json`, `.tmp_transport_capture_validation_20260527/capture_corpus.json`, and `.tmp_transport_capture_validation_20260527/transport_capture_validation_report.json`
    - parameters: profile `reliable-airgap-v1`, classification `lab`, capture medium `print-scan`, payload size `64`, seed `20260527`, `--require-captures`, `--require-distinct-capture-images`, `--require-capture-attachment-report`, `--require-physical-print-scan`
    - result: empty prepared kit failed closed with `capture_images_missing`, `capture_reference_not_distinct`, `capture_attachment_report_mismatch`, and `capture_print_scan_evidence_missing`
    - note: this is a readiness preflight only; it does not run recovery and does not certify real camera/photo or physical print-scan readiness
  - transport evidence archive contract:
    - CLI command: `soenc transport archive-evidence`
    - schema: `enc2sop-transport-capture-evidence-archive/v1`
    - packaged artifacts: `transport_reliability_report.json`, `capture_corpus.json`, `transport_capture_attachment_report.json`, payloads, manifests, captured images, raw camera images, generated reference images, and recovery outputs when present
    - archive creation gates: `--require-successful-report`, `--require-profile-certified`, `--require-capture-attachment-report`, `--require-physical-print-scan`, `--require-real-camera-perspective-correction`, and `--require-ocr-only-backend`
    - claim packaging boundary: a physical print-scan, real-camera perspective, or OCR-only archive cannot be created with its corresponding `--require-*` flag unless the input report both required and passed that exact gate
    - replay verification command: `soenc transport verify-evidence-archive`
    - replay verification schema: `enc2sop-transport-capture-evidence-archive-verification/v1`
    - verification checks: embedded/external manifest parity, safe ZIP member paths, exact archive inventory, per-file SHA256/size, archived report/corpus/attachment JSON schemas, summary role counts, and requested gate state such as successful report, profile-certified, attachment-report, physical print-scan, real camera perspective-correction, or OCR-only backend gates
    - local evidence: `.tmp_transport_evidence_archive_20260527/transport_capture_evidence_archive.zip` and `.tmp_transport_evidence_archive_20260527/transport_capture_evidence_archive_manifest.json`
    - parameters: archived `.tmp_transport_attachment_lineage_20260527/cert/transport_reliability_report.json` with `--require-successful-report --require-capture-attachment-report`
    - result: archive manifest recorded 8 hash-bound files and final ZIP SHA256 `47141c48712e991038a39441b73e93f7e127c6988e2d0099cc7ee2d6bcbe3e13`
    - note: this packages replay evidence only; because the input corpus was fixture-based, it does not certify real camera/photo or physical print-scan readiness
  - transport evidence archive executable replay:
    - CLI command: `soenc transport replay-evidence-archive`
    - schema: `enc2sop-transport-capture-evidence-archive-replay/v1`
    - behavior: verifies the archive first, extracts archive members, rewrites archived `capture_corpus.json` and attachment report paths to extracted files, reruns recovery for the archived capture corpus, and compares replayed case success/failure reason plus payload/restored digest evidence to the archived measured report
    - local evidence: `.tmp_transport_archive_replay_20260527/replay/transport_evidence_archive_replay_report.json`
    - parameters: fixture-based lab print-scan archive with `--require-successful-report --require-profile-certified --require-capture-attachment-report --require-physical-print-scan`
    - result: replay succeeded with `mismatch_count=0`; archive ZIP SHA256 `53956c032d42fa7bdf05aecd434b7f1f4362980f991ded65055a337c5328ba93`
    - note: this proves archive replay execution only; because the capture image was fixture-based, it does not certify real camera/photo or physical print-scan readiness
  - real camera raw-photo kit contract evidence:
    - CLI flags: `--include-raw-capture-dirs`, `--perspective-correction-method`, and `attach-capture-corpus --require-raw-captures`
    - local evidence: `.tmp_transport_camera_raw_kit_20260527/capture_kit_manifest.json`, `.tmp_transport_camera_raw_kit_20260527/capture_corpus.json`, and `.tmp_transport_camera_raw_kit_20260527/transport_capture_attachment_report.json`
    - parameters: classification `real`, capture medium `camera-photo`, payload size `64`, seed `20260527`, raw capture dirs enabled, perspective method `operator-supplied homography correction`, `--require-captures`, `--require-raw-captures`, `--require-distinct-capture-images`
    - result: kit staging created one corrected-image directory plus one `captures/*__raw` directory and wrote `raw_image_paths`/`perspective_correction` into the corpus; attachment on the empty kit failed closed with `capture_images_missing`, `raw_capture_images_missing`, and `capture_reference_not_distinct`, proving raw camera evidence cannot be implied from the staged kit alone
  - strict capture-gate evidence:
    - local evidence: `.tmp_transport_capture_distinct_gate_20260526/capture_kit_manifest.json`, `.tmp_transport_capture_distinct_gate_20260526/capture_corpus.json`, and `.tmp_transport_capture_distinct_gate_20260526/cert/transport_reliability_report.json`
    - parameters: profile `reliable-airgap-v1`, classification `lab`, payload size `64`, seed `20260526`, backend `sidecar`, `--capture-corpus-only`, `--capture-required-classification lab`, `--require-distinct-capture-images`
    - result: copied generated pages recovered successfully but report failed closed with `capture_reference_not_distinct`, proving fixture copies cannot be counted as physical/lab capture evidence
  - real camera perspective-correction evidence gate:
    - local evidence: `.tmp_transport_camera_perspective_gate_20260526/capture_kit_manifest.json`, `.tmp_transport_camera_perspective_gate_20260526/capture_corpus.json`, and `.tmp_transport_camera_perspective_gate_20260526/cert/transport_reliability_report.json`
    - parameters: profile `reliable-airgap-v1`, classification `real`, payload size `64`, seed `20260526`, backend `sidecar`, `--capture-corpus-only`, `--capture-required-classification real`, `--capture-required-success-rate 1.0`, `--require-real-camera-perspective-correction`
    - result: fixture-copied corrected images recovered successfully but report failed closed with `capture_perspective_evidence_missing`, proving corrected-only/generated fixtures cannot be counted as real camera perspective-correction evidence
  - physical print-scan evidence gate:
    - CLI flag: `--require-physical-print-scan`
    - prepared capture kits can now stage `capture_medium=print-scan` through `--capture-medium print-scan`
    - reports include per-case `physical_print_scan_evidence`, top-level `capture_medium_counts`, and `physical_print_scan_passed` threshold state
    - local evidence: `.tmp_transport_print_scan_gate_20260526/capture_kit_manifest.json`, `.tmp_transport_print_scan_gate_20260526/capture_corpus.json`, and `.tmp_transport_print_scan_gate_20260526/cert/transport_reliability_report.json`
    - parameters: profile `reliable-airgap-v1`, classification `lab`, capture medium `print-scan`, payload size `64`, seed `20260526`, backend `sidecar`, `--capture-corpus-only`, `--capture-required-classification lab`, `--capture-required-success-rate 1.0`, `--require-physical-print-scan`
    - result: fixture-copied generated pages recovered successfully but report failed closed with `capture_print_scan_evidence_missing`, proving generated fixtures and metadata alone cannot be counted as physical print-scan evidence
  - backend-specific OCR-only evidence gate:
    - CLI flag: `--require-ocr-only-backend`
    - capture-kit flag: `prepare-capture-corpus --ocr-only-backend {tesseract,easyocr,external}`
    - preflight flag: `validate-capture-corpus --require-ocr-only-backend`
    - staged OCR-only kits use non-production profile `ocr-only-backend-v1` and sidecar-free generated pages
    - optional threshold gate: `--ocr-only-required-success-rate`
    - reports include top-level `ocr_only_certification`, per-case `ocr_only_evidence`, `thresholds.ocr_only_backends`, and summary `ocr_only_*` backend counts/rates
    - gate requires a non-sidecar OCR backend (`tesseract`, `easyocr`, or `external`), matching selected OCR backend, successful recovery, and no binary sidecar in the generated/captured page manifest
    - OCR-only reports are explicitly not `reliable-airgap-v1` production proof and do not certify generic OCR fallback

Minimum distortions:

- PNG/JPEG compression
- resize/downscale/upscale
- small rotation
- crop/margin loss
- blur
- contrast/brightness changes
- perspective skew
- screenshot-like and print-scan-like degradation

### `ENC-P1-020` Stronger FEC If Data Requires It

Current parity can recover one missing chunk per parity group. If reliability reports show multi-chunk loss in a group is common, implement stronger FEC such as Reed-Solomon or an equivalent bounded dependency.

### `ENC-P1-021` Transport Operator UX

Add operator-facing guardrails:

- `soenc transport plan`
- `soenc transport self-test`
- `soenc transport certify`
- explicit retake instructions
- explicit "not GA-certified" warning for OCR-only fallback

## 7. Next Recommended Card

The next recommended card for broad product launch readiness is:

`ENC-P0-019`

If a live GitHub protected-branch/environment can be executed immediately, `ENC-P0-016` may be closed first. Otherwise, continue `ENC-P0-019` with real-world transport evidence: real camera/photo capture corpus, full print-scan corpus, real perspective correction evidence, or backend-specific OCR-only measured reports.

