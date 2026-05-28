You are continuing the `enc2sop` platform build toward production launch.

## Mandatory Baseline

Read these files in this exact order at the start of every automation run:

1. `docs/PRODUCT_LAUNCH_ROADMAP_2026-05-25.md`
2. `docs/PLATFORM_LAUNCH_ASSESSMENT_2026-05-06.md`
3. `docs/IMPLEMENTATION_TASK_CARDS.md`

Treat those three files as the active product-launch baseline. This prompt is only the automation handoff contract; if it conflicts with those files, follow the three baseline documents and update this prompt.

## Current State As Of 2026-05-27

- Mainline product core remains `protect -> build -> package -> verify -> release`.
- QR/OCR/airgap transport remains optional and must not block mainline-only Beta.
- Linux pre-production acceptance already passed against a real project (`omniprompt-gateway`) with `[9/9] Acceptance checks passed`.
- `ENC-P0-016` remains blocked on real protected-branch/environment GitHub CI execution and archived evidence.
- `ENC-P0-017` is done:
  - `soenc transport certify` exists.
  - `transport_reliability_report.json` uses schema `enc2sop-transport-reliability-report/v1`.
  - local `digital-sidecar-v1` evidence passed `2/2` generated-page sidecar cases at success rate `1.0`.
- `ENC-P0-018` is done:
  - `soenc transport certify --profile reliable-airgap-v1` exists.
  - production profile checks fail closed when sidecar, line CRC, compact page/hash metadata, manifest-guided line indexing, or redundancy/parity requirements are weakened.
  - local `reliable-airgap-v1` evidence passed `2/2` generated-page sidecar cases at success rate `1.0` with `profile_certified=true`.
- `ENC-P0-019` is in progress:
  - `soenc transport certify --distortion-suite generated-page-basic-v1` exists.
  - `soenc transport certify --distortion-suite generated-page-stress-v1` exists and passes the generated-page synthetic stress suite.
  - `soenc transport certify --capture-corpus-file ...` exists for operator-supplied real/lab/synthetic/stress-only capture corpus attachment.
  - `soenc transport prepare-capture-corpus` exists for staging physical/lab capture kits with schema `enc2sop-transport-capture-kit/v1`.
  - `soenc transport prepare-capture-corpus --include-raw-capture-dirs` exists for staging camera perspective-correction kits with `captures/*__raw` raw-photo directories, per-case `raw_image_paths`, and `perspective_correction` metadata.
  - `soenc transport prepare-capture-corpus --ocr-only-backend {tesseract,easyocr,external}` exists for staging sidecar-free OCR-only capture kits under non-production profile `ocr-only-backend-v1`; generated manifests explicitly record `sidecar_enabled=false`.
  - `soenc transport correct-capture-perspective` exists for prepared camera kits; it reads staged `raw_image_paths`, writes corrected images into corpus `image_path`, emits `enc2sop-transport-capture-perspective-correction-report/v1` with raw/corrected/reference SHA256 bindings, and supports deterministic `copy`, EXIF `normalize`, or operator-corner `four-point` correction modes. It is preparation evidence only, not recovery certification or real camera readiness.
  - `soenc transport ingest-capture-corpus` exists for externally returned lab/real photo or scan folder trees. It maps one subdirectory per case label into a prepared `capture_corpus.json`, optionally maps a raw-photo root, writes `enc2sop-transport-capture-corpus-ingestion-report/v1`, records per-file SHA256/size bindings plus metadata/classification/medium, and refreshes the kit manifest without claiming recovery certification.
  - `soenc transport attach-capture-corpus --require-raw-captures` exists and fails closed with `raw_capture_images_missing` until every staged camera case has raw-photo images attached.
  - `soenc transport validate-capture-corpus` exists and writes `enc2sop-transport-capture-corpus-validation/v1`, a pre-certification readiness report for operator capture corpora. It checks profile compliance, attached/reference/raw image SHA256s, distinctness, attachment-report lineage, and optional print-scan, real-camera perspective, or OCR-only backend gates without running recovery or certifying a medium.
  - `soenc transport certify --require-capture-attachment-report` exists and fails closed with `capture_attachment_report_mismatch` unless the current capture/raw/reference image path, size, and SHA256 records match `transport_capture_attachment_report.json`.
  - `--require-capture-provenance` exists on `certify`, `validate-capture-corpus`, and `certify-capture-evidence`; it fails closed with `capture_provenance_missing` unless lab/real cases declare a capture medium and record session, operator, timestamp, and capture-device metadata (`capture_session_id`, `operator`, `captured_at_utc`, and scanner/camera/printer identity). This is provenance evidence only and does not certify a medium by itself.
  - `soenc transport archive-evidence` exists and writes `transport_capture_evidence_archive.zip` plus `transport_capture_evidence_archive_manifest.json` (`enc2sop-transport-capture-evidence-archive/v1`) for a measured transport report and referenced artifacts; archive creation can fail closed on `--require-profile-certified`, `--require-physical-print-scan`, `--require-real-camera-perspective-correction`, or `--require-ocr-only-backend` unless the input report required and passed the same gate.
  - `soenc transport verify-evidence-archive` exists and writes/prints `enc2sop-transport-capture-evidence-archive-verification/v1`, failing closed on embedded/external manifest drift, unsafe/extra/missing ZIP members, per-file SHA256/size mismatch, archived report/corpus/attachment schema mismatch, or requested gate mismatch. Workspace-relative external manifest paths are accepted before archive-directory-relative fallback.
  - `soenc transport replay-evidence-archive` exists and writes/prints `enc2sop-transport-capture-evidence-archive-replay/v1`; it verifies the ZIP, extracts archived bytes, rewrites archived corpus and attachment-report paths to extracted files, reruns recovery for the archived capture corpus, and compares replayed case outcomes to the archived measured report without broadening any certification claim.
  - `soenc transport certify-capture-evidence` exists and writes/prints `enc2sop-transport-capture-certification-pipeline/v1`; it runs attach, validate, certify, archive, verify, executable archive replay, and certification-status in order. It fails closed before status if archive replay fails or diverges, and supports `--replay-output-dir`, `--replay-report-file`, and `--replay-summary-file` for handoff paths.
  - `transport_reliability_report.json`, evidence archive manifests, and archive verification reports now include machine-readable `certification_claims` (`enc2sop-transport-certification-claims/v1`). The claims block explicitly labels `generated-page-sidecar`, `generated-page-synthetic-stress`, `physical-print-scan`, `real-camera-perspective-correction`, and `backend-specific-ocr-only` as certified or not certified for the measured report, with evidence level and missing gates.
  - `soenc transport certification-status` exists and writes/prints `enc2sop-transport-certification-status/v1` from a measured report, a verification report, or a freshly verified evidence archive. It summarizes source SHA256, profile state, certified/uncertified claims, evidence level, missing gates, and recommended next evidence steps for launch review without broadening the underlying measured claims. It also supports `--require-certified-claim <claim>` as a fail-closed launch/checklist gate; the JSON still writes but `success=false` and the CLI exits non-zero if any requested claim is not already certified by the underlying evidence.
  - capture corpus reports record case labels, source image SHA256 values, optional capture metadata, backend, success/failure reason, corpus classification, and fail-closed reliable-airgap profile checks against attached manifests.
  - capture corpus certification now has explicit physical/lab evidence gates: `--capture-required-classification`, `--capture-required-success-rate`, and `--require-distinct-capture-images`. Prepared kits bind generated `reference_image_paths`, and strict reports fail closed with `capture_reference_not_distinct` if attached capture images are byte-identical fixture copies.
  - real camera perspective-correction certification now has an explicit non-default gate: `--require-real-camera-perspective-correction`. It requires `real` corpus cases with raw camera `raw_image_paths`, corrected recovery images in `image_path`, generated `reference_image_paths`, `perspective_correction.applied=true` plus a method, and byte-distinct raw/corrected/reference image sets.
  - physical print-scan certification now has an explicit non-default gate: `--require-physical-print-scan`. Prepared kits support `--capture-medium print-scan`; strict reports require `lab` or `real` corpus cases with `capture_medium=print-scan`, generated `reference_image_paths`, byte-distinct scanned images in `image_path`, and printer/scanner/dpi metadata.
  - backend-specific OCR-only certification now has an explicit non-default gate: `--require-ocr-only-backend`. It requires backend `tesseract`, `easyocr`, or `external`, sidecar-free pages, selected OCR backend parity, and measured per-backend threshold reporting. Sidecar-free OCR-only capture kits and validation preflights can be staged without code changes, but they are not recovery certification by themselves.
  - the report records per-distortion parameters, image digests, success rates, threshold gates, and failure reason counts.
  - local `reliable-airgap-v1` + `generated-page-basic-v1` evidence passed `12/12` generated-page distortion cases at success rate `1.0` with `profile_certified=true`.
  - local `reliable-airgap-v1` + `generated-page-stress-v1` evidence passed `13/13` generated-page synthetic stress distortion cases at success rate `1.0` with `profile_certified=true`.
  - local capture-kit contract evidence exists at `.tmp_transport_capture_kit_20260526/`: kit staging produced `2` lab cases and `8` generated page images; controlled fixture certification passed `2/2` after copying generated pages into the capture directories. This proves the attachment/replay contract only, not real scanner/camera readiness.
  - local strict capture-gate evidence exists at `.tmp_transport_capture_distinct_gate_20260526/`: fixture-copied generated pages recovered successfully but strict certification failed closed with `capture_reference_not_distinct`, proving generated fixture copies cannot be counted as physical/lab capture evidence.
  - local real-camera perspective gate evidence exists at `.tmp_transport_camera_perspective_gate_20260526/`: fixture-copied corrected pages recovered successfully but strict certification failed closed with `capture_perspective_evidence_missing`, proving corrected-only/generated fixtures cannot be counted as real camera perspective-correction evidence.
  - local camera raw-photo kit contract evidence exists at `.tmp_transport_camera_raw_kit_20260527/`: kit staging created corrected-image and raw-photo drop directories; attachment on the empty kit failed closed with `capture_images_missing`, `raw_capture_images_missing`, and `capture_reference_not_distinct`, proving raw camera evidence cannot be implied from staged directories alone.
  - local attachment-report lineage evidence exists at `.tmp_transport_attachment_lineage_20260527/`: fixture-based lab attachment certified only while image digests matched `transport_capture_attachment_report.json`; after capture drift, certification failed closed with `capture_attachment_report_mismatch`.
  - local capture-corpus validation preflight evidence exists at `.tmp_transport_capture_validation_20260527/`: an empty prepared lab print-scan kit failed closed with `capture_images_missing`, `capture_reference_not_distinct`, `capture_attachment_report_mismatch`, and `capture_print_scan_evidence_missing`, proving operators can find missing physical evidence before a certification run. This is readiness validation only, not real scanner/camera certification.
  - local evidence-archive packaging evidence exists at `.tmp_transport_evidence_archive_20260527/`: `archive-evidence` packaged the fixture-based attachment-lineage report into an 8-file ZIP with SHA256 `47141c48712e991038a39441b73e93f7e127c6988e2d0099cc7ee2d6bcbe3e13`. This proves replay packaging only, not real physical/camera readiness.
  - local evidence-archive verification contract exists: `verify-evidence-archive` verifies archive inventory, embedded/external manifests, file digests/sizes, archived JSON schemas, and requested gate state. This proves archive integrity only, not real physical/camera readiness.
  - local evidence-archive replay contract exists at `.tmp_transport_archive_replay_20260527/`: `replay-evidence-archive` reran fixture-based lab print-scan recovery from archived bytes and produced `mismatch_count=0`, archive SHA256 `53956c032d42fa7bdf05aecd434b7f1f4362980f991ded65055a337c5328ba93`. This proves executable replay plumbing only, not real physical/camera readiness.
  - local strict archive-gate evidence exists at `.tmp_transport_archive_strict_gate_20260527/`: fixture-based lab print-scan evidence archives successfully with `--require-successful-report --require-profile-certified --require-capture-attachment-report --require-physical-print-scan`, ZIP SHA256 `37866ab6f7db602537c26e749a866596741628b2aafbb3a1fb1b627110609013`, and fails closed when the same report is archived with `--require-real-camera-perspective-correction`.
  - local physical print-scan gate evidence exists at `.tmp_transport_print_scan_gate_20260526/`: fixture-copied generated pages recovered successfully but strict certification failed closed with `capture_print_scan_evidence_missing`, proving generated fixtures and metadata alone cannot be counted as physical print-scan evidence.
  - local OCR-only kit/preflight evidence at `.tmp_transport_ocr_only_kit_20260527/` proves `--ocr-only-backend tesseract` stages sidecar-free capture corpora under `ocr-only-backend-v1`, and `validate-capture-corpus --require-ocr-only-backend` recognizes the sidecar-free/backend gate while still failing overall until operator captures are attached. Unit evidence also rejects sidecar-present corpora before certification. This is readiness validation only; no real backend OCR-only threshold report has been archived yet.
  - local certification-status claim-gate evidence proves `--require-certified-claim physical-print-scan` fails closed on generated-page-only evidence with `claim_gate.missing_required_certified_claims=["physical-print-scan"]`; this is a launch/checklist guard only and does not certify any new medium.
  - real camera/photo, full physical print-scan, real camera perspective correction, and generic OCR fallback are still not production-certified because no physical/operator corpus or real backend OCR-only threshold corpus has been archived yet.
- The next local product-readiness slice is continuing `ENC-P0-019` unless real GitHub protected-branch/environment execution is immediately available.
- Product launch framing:
  - mainline-only external Beta remains gated mainly by `ENC-P0-016` live protected-environment evidence.
  - Beta that advertises airgap/QR/OCR transfer needs `ENC-P0-019` real-world or explicitly labeled lab-corpus evidence for the claimed medium.
  - GA/platformization needs both the mainline release evidence and a clear certification boundary for optional transports.

## Card Selection

1. If live GitHub protected-branch/environment execution is available, select `ENC-P0-016` and close real CI promotion evidence.
2. Otherwise select `ENC-P0-019` and continue deterministic distortion corpus certification for realistic cross-medium transport degradation.
3. Do not select optional P1 cards until all P0 launch gaps are either done or explicitly blocked.

## Primary Local Product Goal

Close the next concrete product-launch functionality gap, not another planning-only loop.

Already delivered for `ENC-P0-019`:

- `--distortion-suite generated-page-basic-v1`
- `--distortion-suite generated-page-stress-v1`
- `--capture-corpus-file` with schema `enc2sop-transport-capture-corpus/v1`
- `--capture-corpus-only` for measuring attached captures without rerunning generated cases
- `soenc transport prepare-capture-corpus` stages deterministic pages, capture directories, `capture_corpus.json`, `capture_kit_manifest.json`, and operator instructions
- `soenc transport ingest-capture-corpus` maps externally returned capture folders into a prepared corpus before attachment/certification, so the next real/lab corpus can be added without code or JSON hand-editing
- `soenc transport attach-capture-corpus` records SHA256 bindings for operator photos/scans already placed in prepared capture directories before the certification run
- `soenc transport validate-capture-corpus` preflights attached capture corpora and exact claim gates before running recovery certification
- `--require-capture-attachment-report` binds certification to the attachment report so physical/operator files cannot drift silently between attach and certify
- `--require-capture-provenance` binds real/lab capture measurements to operator/session/device metadata and fails before measurement when provenance is missing
- `soenc transport archive-evidence` packages a measured report/corpus/attachment report and referenced artifacts into a replayable ZIP plus versioned manifest, and can require the exact medium/backend gate being packaged
- `soenc transport verify-evidence-archive` verifies archive integrity and requested gate state before handoff or audit replay
- `soenc transport replay-evidence-archive` reruns recovery from archived bytes and fails closed when replayed case outcomes diverge from the archived report
- `soenc transport certify-capture-evidence` runs the full operator-capture evidence chain, including optional external capture-folder ingestion and archive replay, with one fail-closed command
- `soenc transport certification-status` generates the launch-readable certification matrix from a report or verified archive; product copy should use this artifact and only quote rows with `certified=true`; launch/checklist automation can add `--require-certified-claim <claim>` and fail closed when the claim is not certified
- `--include-raw-capture-dirs` and `--require-raw-captures` stage and hash-bind raw camera photos separately from corrected recovery images
- `correct-capture-perspective` can create corrected capture images from raw-photo paths and bind them in a versioned preparation report before the normal attach/validate/certify/archive/status chain
- `--ocr-only-backend` stages sidecar-free backend-specific OCR-only capture kits, and `validate-capture-corpus --require-ocr-only-backend` preflights the sidecar-free/backend gate before recovery certification
- replayable per-case distortion records and distorted image SHA256 bindings
- replayable per-case operator capture records with source/attached image SHA256 bindings, corpus classification, optional capture metadata, backend, and success/failure reason
- replayable reference-image comparison records for capture corpora, plus explicit capture classification/success/distinct-image gates
- replayable real-camera perspective-correction evidence records for capture corpora, plus a non-default strict gate
- replayable backend-specific OCR-only evidence records, plus a non-default strict gate requiring sidecar-free pages
- per-distortion threshold gates
- fail-closed capture profile checks under `reliable-airgap-v1`
- passing basic generated-page evidence for control, PNG re-encode, JPEG recompression, mild blur, mild contrast/brightness, and screenshot-like high-quality recompression
- passing generated-page synthetic stress evidence for resize down/up, small rotation, crop/margin loss, deterministic skew approximation, sparse noise, and print-scan-like grayscale/contrast/blur approximation

Preferred next `ENC-P0-019` implementation slices, in priority order:

1. Replace the fixture images in a prepared kit's `captures/*` directories with actual `real` or `lab` camera/photo or physical print-scan images. If the operator returns a separate folder tree, prefer the one-command path with `soenc transport certify-capture-evidence --capture-corpus-file ... --capture-root <returned-captures> --require-captures --capture-required-classification <lab|real> --require-distinct-capture-images --require-capture-attachment-report --require-capture-provenance` plus `--raw-capture-root <returned-raw-photos> --require-raw-captures` for camera evidence, capture metadata (`capture_session_id`, `operator`, `captured_at_utc`, scanner/camera/printer identity), the intended medium/backend gate, and matching `--require-certified-claim <claim>`. The pipeline now hash-binds external captures during ingestion, validates readiness, measures recovery, archives evidence, verifies the archive, replays recovery from archived bytes, and writes launch status. Use the individual ingest/attach/validate/certify/archive/verify/replay/status commands only when debugging a failed step or customizing handoff paths.
2. For camera correction claims, stage with `--include-raw-capture-dirs`, place uncorrected photos in `captures/*__raw`, either place externally corrected images in `captures/*` or run `correct-capture-perspective --mode four-point` after recording per-case `perspective_correction.source_corners`, run `attach-capture-corpus --require-captures --require-raw-captures --require-distinct-capture-images`, then run certification with `--require-capture-attachment-report --require-real-camera-perspective-correction`.
3. For physical print-scan claims, stage or set `capture_medium=print-scan`, record printer/scanner/dpi plus capture provenance metadata, replace generated fixture files with real scans, and run with `--require-capture-attachment-report --require-capture-provenance --require-physical-print-scan`.
4. Run backend-specific OCR-only certification only when a real OCR backend/corpus is available: use `--require-ocr-only-backend`, a non-sidecar backend, sidecar-free pages, and a measured threshold. Do not make generic OCR fallback production-certified without measured backend evidence.
5. Preserve the existing generated-page sidecar certification path and keep `reliable-airgap-v1` as the only production airgap profile unless stronger evidence is added.
6. Update docs to state which transport paths are production-certified, lab-certified, synthetic stress-only, or not certified.

## Primary Live-GitHub Goal

If live GitHub execution is available, close `ENC-P0-016` by executing and archiving real protected-branch/environment promotion evidence.

Expected artifacts:

- `release_bundle.json`
- `release_approval.json`
- `release_receipt.json`
- `promotion_evidence.json`
- `promotion_audit_report.json`
- `rotation_rehearsal_report.json`
- `promotion_artifact_audit_report.json`
- `promotion_run_receipt.json`

## Execution Rules

- Prefer concrete code or real operational evidence over more planning.
- Do not keep locally hardening promotion capture if live GitHub execution is unavailable; move product functionality forward with `ENC-P0-019`.
- Do not let optional transport/OCR work delay the mainline launch gate.
- Do not claim optional transport/OCR is Beta/GA-ready until `ENC-P0-019` produces distortion/report evidence for the claimed transfer medium.
- Do not weaken signed approval, manifest integrity, runtime fingerprint, release receipt, promotion evidence, or CI provenance checks.
- Preserve backward compatibility outside the new reliable-airgap profile.
- Update `docs/IMPLEMENTATION_TASK_CARDS.md` in the same iteration.
- Update `docs/PRODUCT_LAUNCH_ROADMAP_2026-05-25.md` or `docs/PLATFORM_LAUNCH_ASSESSMENT_2026-05-06.md` if launch readiness assumptions change.

## Useful Checks

Transport/distortion checks:

- `python -m pytest -q tests/test_transport_certify.py tests/test_qrcode_helper_sidecar.py tests/test_transport_modules.py`

Mainline/promotion checks:

- `python -m pytest -q tests/test_promotion_artifacts.py tests/test_soenc_cli.py tests/test_release_promotion_workflow.py`
- `python -m pytest -q tests/test_encryption_helper.py tests/test_toolchain_profile.py tests/test_soenc_cli.py`

Manual certification sample:

- `python .\soenc.py transport certify -o .tmp_transport_reliable_profile_20260525 --profile reliable-airgap-v1 --payload-size 64 --payload-size 257 --iterations-per-size 1 --seed 20260525 --backend sidecar --chunk-chars 24 --lines-per-page 8 --redundancy-copies 2 --parity-group-size 4 --max-list 20`
- `python .\soenc.py transport certify -o .tmp_transport_distortion_basic_20260525 --profile reliable-airgap-v1 --payload-size 64 --payload-size 257 --iterations-per-size 1 --seed 20260525 --backend sidecar --chunk-chars 24 --lines-per-page 8 --redundancy-copies 2 --parity-group-size 4 --distortion-suite generated-page-basic-v1 --max-list 20`
- `python .\soenc.py transport certify -o .tmp_transport_distortion_stress_next --profile reliable-airgap-v1 --payload-size 64 --iterations-per-size 1 --seed 20260525 --backend sidecar --chunk-chars 24 --lines-per-page 8 --redundancy-copies 2 --parity-group-size 4 --distortion-suite generated-page-stress-v1 --max-list 20`
- `python .\soenc.py transport prepare-capture-corpus -o .tmp_transport_capture_kit_next --classification lab --capture-medium print-scan --payload-size 64 --payload-size 257 --iterations-per-size 1 --seed 20260526 --chunk-chars 24 --lines-per-page 8 --redundancy-copies 2 --parity-group-size 4 --capture-metadata printer=example-printer --capture-metadata scanner=example-flatbed --capture-metadata dpi=300`
- after real photos/scans are placed in `.tmp_transport_capture_kit_next\captures\*`, prefer `python .\soenc.py transport certify-capture-evidence --capture-corpus-file .tmp_transport_capture_kit_next\capture_corpus.json -o .tmp_transport_capture_kit_next\capture_pipeline --kit-manifest-file .tmp_transport_capture_kit_next\capture_kit_manifest.json --profile reliable-airgap-v1 --backend sidecar --chunk-chars 24 --lines-per-page 8 --redundancy-copies 2 --parity-group-size 4 --capture-required-classification lab --require-capture-provenance --require-physical-print-scan --require-certified-claim physical-print-scan --max-list 20`; when captures are returned as a separate folder tree, add `--capture-root <returned-captures> --capture-medium print-scan --capture-metadata scanner=<scanner> --capture-metadata dpi=<dpi> --capture-metadata capture_session_id=<session> --capture-metadata operator=<operator> --capture-metadata captured_at_utc=<timestamp>` so the same pipeline ingests before attachment/certification.
- before certification, run `python .\soenc.py transport validate-capture-corpus --capture-corpus-file .tmp_transport_capture_kit_next\capture_corpus.json --output-file .tmp_transport_capture_kit_next\transport_capture_validation_report.json --profile reliable-airgap-v1 --backend sidecar --require-captures --require-distinct-capture-images --require-capture-attachment-report --require-capture-provenance --capture-required-classification lab --require-physical-print-scan` when the intended claim is physical print-scan.
- after a passing real/lab capture certification, run `python .\soenc.py transport archive-evidence --report-file .tmp_transport_capture_kit_next\cert\transport_reliability_report.json -o .tmp_transport_capture_kit_next\evidence_archive --require-successful-report --require-profile-certified --require-capture-attachment-report`, then run `python .\soenc.py transport verify-evidence-archive --archive-file .tmp_transport_capture_kit_next\evidence_archive\transport_capture_evidence_archive.zip --manifest-file .tmp_transport_capture_kit_next\evidence_archive\transport_capture_evidence_archive_manifest.json --require-successful-report --require-profile-certified --require-capture-attachment-report`, then run `python .\soenc.py transport replay-evidence-archive --archive-file .tmp_transport_capture_kit_next\evidence_archive\transport_capture_evidence_archive.zip --manifest-file .tmp_transport_capture_kit_next\evidence_archive\transport_capture_evidence_archive_manifest.json -o .tmp_transport_capture_kit_next\evidence_replay --require-successful-report --require-profile-certified --require-capture-attachment-report`, then run `python .\soenc.py transport certification-status --archive-file .tmp_transport_capture_kit_next\evidence_archive\transport_capture_evidence_archive.zip --manifest-file .tmp_transport_capture_kit_next\evidence_archive\transport_capture_evidence_archive_manifest.json --verify-archive --require-certified-claim physical-print-scan --output-file .tmp_transport_capture_kit_next\evidence_archive\transport_certification_status.json` when the intended claim is physical print-scan.
- for real camera perspective correction, first stage a kit with `python .\soenc.py transport prepare-capture-corpus -o .tmp_transport_camera_raw_kit_next --classification real --capture-medium camera-photo --include-raw-capture-dirs --perspective-correction-method "operator-supplied homography correction" --payload-size 64 --iterations-per-size 1 --seed 20260527 --chunk-chars 24 --lines-per-page 8 --redundancy-copies 2 --parity-group-size 4`; place raw photos in `captures\*__raw` and corrected images in `captures\*`, run `attach-capture-corpus --require-captures --require-raw-captures --require-distinct-capture-images`, then run with `--capture-required-classification real --require-distinct-capture-images --require-capture-attachment-report --require-real-camera-perspective-correction`
- for physical print-scan evidence, use `--capture-required-classification lab --capture-required-success-rate 1.0 --require-distinct-capture-images --require-capture-attachment-report --require-physical-print-scan`
- for OCR-only backend evidence, run `python .\soenc.py transport certify -o .tmp_transport_ocr_only_next --backend tesseract --no-sidecar --payload-size 64 --iterations-per-size 1 --require-ocr-only-backend --ocr-only-required-success-rate 0.99 --max-list 20` only when the named OCR backend is installed and intended to be measured; use `external --ocr-provider-cmd ...` for provider-specific reports

## Required Output

Every iteration must report:

1. selected `card_id`
2. concrete iteration goal
3. implementation or evidence produced
4. changed files
5. verification performed
6. remaining production-launch blockers
7. next recommended card

## Conflict Handling

If the worktree has unrelated changes:

- do not revert them
- adapt if compatible
- if they conflict with the selected card, document the conflict and choose the safest forward path
