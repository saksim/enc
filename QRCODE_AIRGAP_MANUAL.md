# enc2sop Transport Plugin Manual

## 1. Scope

Airgap QR/OCR workflows are optional plugin capabilities.

They are not required for mainline `protect -> build -> package -> verify -> release`.

Plugin entrypoint:

```powershell
python .\soenc.py transport <subcommand> [args]
```

## 2. Recovery Priority (Auto Backend)

When `--backend auto` is used, recovery/extraction order is:

1. sidecar geometric decode
2. manifest-guided structured extraction
3. external OCR provider (`--ocr-provider-cmd`)
4. generic OCR fallback (`tesseract`, then `easyocr`)

This policy is deterministic and aligned with production baseline decisions.

## 3. Subcommands

Transport subcommands are provided by the optional plugin surface:

1. `export`
2. `estimate`
3. `ocr-extract`
4. `analyze`
5. `verify`
6. `recover`
7. `recover-images`
8. `certify`
9. `prepare-capture-corpus`
10. `ingest-capture-corpus`
11. `attach-capture-corpus`
12. `validate-capture-corpus`
13. `package-capture-return`
14. `certify-capture-evidence`
15. `archive-evidence`
16. `verify-evidence-archive`
17. `replay-evidence-archive`
18. `correct-capture-perspective`
19. `archive-ocr-safe-evidence`
20. `verify-ocr-safe-evidence-archive`
21. `certification-status`

## 4. Quick Start

### 4.1 Export

```powershell
python .\soenc.py transport export -i .\artifact.bin -o .\airgap_pkg --filename-prefix page
```

### 4.2 Analyze and Verify

```powershell
$manifest = (Get-ChildItem .\airgap_pkg\*.manifest.json | Select-Object -First 1).FullName

python .\soenc.py transport analyze -m $manifest -t .\airgap_pkg\pages_txt
python .\soenc.py transport verify -m $manifest -t .\airgap_pkg\pages_txt
```

### 4.3 Recover

```powershell
python .\soenc.py transport recover -m $manifest -t .\airgap_pkg\pages_txt -o .\airgap_pkg\restored.bin
```

### 4.4 Recover From Images

```powershell
python .\soenc.py transport recover-images -m $manifest -i .\airgap_pkg\pages -o .\airgap_pkg\restored.bin --backend auto
```

### 4.5 Certify Generated-Page Sidecar Reliability

```powershell
python .\soenc.py transport certify -o .\transport_cert --payload-size 128 --payload-size 4096 --iterations-per-size 1 --backend sidecar
```

This writes `transport_reliability_report.json` using schema `enc2sop-transport-reliability-report/v1`.

Use the production profile when the result is intended to support an airgap Beta claim for generated pages:

```powershell
python .\soenc.py transport certify -o .\transport_cert --profile reliable-airgap-v1 --payload-size 128 --payload-size 4096 --iterations-per-size 1 --backend sidecar --redundancy-copies 2 --parity-group-size 4
```

`reliable-airgap-v1` requires sidecar recovery, manifest-guided certification, line CRC, compact page/hash metadata, SHA256 verification, and redundancy or parity. Unsafe settings fail closed unless explicitly run as experimental with `--allow-unsafe-profile`; those reports set `profile_certified=false`.

Add the basic generated-page distortion suite when the report needs to cover controlled export/re-encode and screenshot-like degradation:

```powershell
python .\soenc.py transport certify -o .\transport_cert --profile reliable-airgap-v1 --payload-size 128 --payload-size 4096 --iterations-per-size 1 --backend sidecar --redundancy-copies 2 --parity-group-size 4 --distortion-suite generated-page-basic-v1
```

Use the generated-page synthetic stress suite when the report needs to cover resize drift, small rotation, crop/margin loss, deterministic skew approximation, sparse noise, and print-scan-like grayscale/contrast/blur approximation:

```powershell
python .\soenc.py transport certify -o .\transport_cert --profile reliable-airgap-v1 --payload-size 128 --payload-size 4096 --iterations-per-size 1 --backend sidecar --redundancy-copies 2 --parity-group-size 4 --distortion-suite generated-page-stress-v1
```

The basic suite records control, PNG re-encode, JPEG recompression, mild blur, mild contrast/brightness shift, and screenshot-like high-quality recompression. The stress suite adds generated-page resize down/up, small rotation, crop/margin loss, deterministic skew approximation, sparse noise, and print-scan-like approximation. Real camera photos, generic OCR fallback, and full physical print/scan degradation remain non-GA-certified unless a report explicitly measures and passes those cases.

### 4.5.1 OCR-Safe Human-Correctable Profile

When no real scan/photo corpus is available, use the OCR-safe profile to exercise the text repair path without relying on ambiguous glyphs at generation time:

```powershell
python .\soenc.py transport export -i .\artifact.bin -o .\airgap_ocr_safe --payload-alphabet-profile ocr-safe-human-correctable-v1 --no-sidecar
```

The profile emits only `12356789OAEFHJKMNPRUVWXY` in payload text and records `payload_alphabet_profile=ocr-safe-human-correctable-v1` plus the alphabet in manifests and reports. Decode normalizes hard-safe OCR confusions, expands ambiguous candidates, accepts a line only when exactly one candidate passes line CRC, and still requires final payload SHA256 before recovery succeeds.

To produce replayable synthetic evidence for the OCR-safe confusion families, run:

```powershell
python .\soenc.py transport certify-ocr-confusion -o .\ocr_confusion_cert
```

This writes `synthetic_ocr_confusion_report.json` with schema `enc2sop-transport-ocr-safe-confusion-report/v1`. The suite injects `6/G/g`, `9/g/q`, `2/7/Z/z`, `O/0/o/Q/D`, `1/I/i/l/L`, `5/S/s`, `8/B/b`, whitespace insertion, dash/noise insertion, and line-break drift, records the canonical `required_confusion_cases[]` contract, then records per-case analyze/recovery outputs and final payload SHA256 verification. This proves deterministic synthetic text repair only; it is not real camera/photo, physical print-scan, or backend-specific OCR certification.

Verify the saved synthetic report and referenced artifacts before handing it to launch/audit review:

```powershell
python .\soenc.py transport verify-ocr-confusion --report-file .\ocr_confusion_cert\synthetic_ocr_confusion_report.json --output-file .\ocr_confusion_cert\synthetic_ocr_confusion_verification_report.json
```

This writes `enc2sop-transport-ocr-safe-confusion-report-verification/v1`, re-checks the source report schema/profile/suite, payload and manifest SHA256 bindings, generated source-page text digests, mechanical mutation replay, per-case OCR text/analyze/recovered artifact digests, required confusion-family coverage, exact required-case-suite coverage, and final recovered payload SHA256 parity. It verifies replayability for synthetic OCR-safe text-confusion evidence only; it still does not certify real camera/photo, physical print-scan, or backend-specific OCR transfer.

For unresolved or multi-pass OCR-safe lines, write a replayable operator template:

```powershell
python .\soenc.py transport analyze -m .\airgap_ocr_safe\PAYLOAD.manifest.json -t .\ocr_text.txt --strict-payload-chars --emit-corrections-template .\corrections_template.csv
```

The CSV columns are `page,line,raw_text,normalized_text,candidates,status,expected_crc,actual_crc,corrected_text`. Passing synthetic confusion tests or generated-page sidecar certification with this profile does not certify real camera/photo, physical print-scan, or backend-specific OCR readiness; those still require measured capture/backend evidence and matching `certification-status --require-certified-claim ...` gates.

After an operator fills `corrected_text`, replay it into a versioned report:

```powershell
python .\soenc.py transport replay-corrections -m .\airgap_ocr_safe\PAYLOAD.manifest.json -t .\ocr_text.txt --apply-corrections-file .\corrections_template.csv -o .\recovered.bin --report-file .\transport_ocr_correction_replay_report.json --strict-payload-chars
```

`replay-corrections` writes `enc2sop-transport-ocr-correction-replay/v1`, records applied/invalid correction rows, rejects stale generated-template rows when their `raw_text`, `normalized_text`, `status`, or `actual_crc` no longer match the current unresolved OCR line, reports unused filled rows with row number, page, line, expected CRC, and corrected-text SHA256, and writes the recovered artifact only after final compressed/raw SHA256 checks pass and the correction replay itself is accepted with no invalid, unused, malformed, or still-required correction rows. Malformed correction CSVs, such as files missing `corrected_text`, now produce a failed replay report with `correction_file_valid=false`, a structured `correction_file_error`, and suppressed output. On failed replay it records `requested_output_file` plus `output_suppressed_reason`, and with unresolved current lines writes a refreshed retry template beside `--report-file` as `corrections_template_retry.csv` unless `--emit-corrections-template` is supplied. It preserves the same certification boundary: it proves text-correction replay for the supplied OCR text, not real camera, physical print-scan, or backend-specific OCR readiness.

Verify the saved correction replay report before handing it to launch/audit review:

```powershell
python .\soenc.py transport verify-correction-replay --report-file .\transport_ocr_correction_replay_report.json --output-file .\transport_ocr_correction_replay_verification_report.json
```

`verify-correction-replay` writes `enc2sop-transport-ocr-correction-replay-verification/v1`, re-checks the replay report schema/profile, referenced manifest/OCR/correction files, correction CSV digest, mechanical replay result, final payload SHA256 state, and recovered-output or suppressed-output state. It verifies replayability for the specific correction handoff only and does not certify real camera/photo, physical print-scan, or backend-specific OCR transfer.

Package OCR-safe synthetic and correction replay evidence for handoff:

```powershell
python .\soenc.py transport archive-ocr-safe-evidence --archive-file .\ocr_safe_evidence_archive.zip --manifest-file .\ocr_safe_evidence_archive_manifest.json --confusion-report-file .\ocr_confusion_cert\synthetic_ocr_confusion_report.json --correction-replay-report-file .\transport_ocr_correction_replay_report.json --require-confusion-report --require-correction-replay-report --require-source-report-verification
```

Verify the archive before audit or launch review:

```powershell
python .\soenc.py transport verify-ocr-safe-evidence-archive --archive-file .\ocr_safe_evidence_archive.zip --manifest-file .\ocr_safe_evidence_archive_manifest.json --output-file .\ocr_safe_evidence_archive_verification.json --require-confusion-report --require-correction-replay-report --require-source-report-verification
```

`archive-ocr-safe-evidence` writes `enc2sop-transport-ocr-safe-evidence-archive/v1` and packages the included report plus referenced payload, manifest, OCR text, correction CSV, output, source-page text, and case artifact files with SHA256/size inventory. With `--require-source-report-verification`, archive creation first reruns `verify-ocr-confusion` and/or `verify-correction-replay`, fails before writing the ZIP if any included source report is stale, any report/source-verifier state field is malformed, or any fixed rewritten-report/source-verifier archive member collides with an already reserved member, records source-verification role/digest/size/path metadata in the archive manifest, stores the full source-verification JSON as an archive member, and summarizes source-verification count/roles. `verify-ocr-safe-evidence-archive` writes `enc2sop-transport-ocr-safe-evidence-archive-verification/v1`, checks ZIP member inventory through `archive_inventory_verified`, ZIP member safety, external manifest envelope metadata (`archive_sha256`, `archive_size_bytes`, `archive_file`, `manifest_file`, and `embedded_manifest_sha256`), embedded/external manifest parity including `generated_at_utc`, canonical archive timestamp format, canonical per-file and report-entry SHA256/byte-size/path metadata, report-role uniqueness through `archive_report_roles_verified`, report schema/role binding through `archive_report_schemas_verified`, report-level source-path parity through `archive_report_source_paths_verified`, source-path identity uniqueness through `archive_source_paths_verified`, manifest file-member SHA256/byte-size replay with `manifest_file_metadata_verified=false` on payload drift, manifest success, the exact synthetic-only certification boundary, typed parameter gates, typed report/source-verification state flags, manifest summary file-count/total-size, report-count/report-role, source-verification count/role, source-report role ownership through `source_report_archive_roles_verified`, source-verifier role ownership through `source_report_verification_roles_verified`, including the report-level `source_verification.role` metadata and file-record role, file-role parity, role-to-archive-path semantics, source-report archive metadata parity between `source_report_archive`, `source_verification.source_report_archive_*`, and archived source-report bytes, source-report archive-entry path/SHA256/size metadata, source-verification archive-entry path/SHA256/size metadata, source-verification manifest entry-set parity with no unreferenced source-verifier/source-report members, rewritten report manifest entry-set parity with no unreferenced report members, fixed rewritten-report path parity through `archive_report_fixed_paths_verified`, fixed source-verifier path parity through `source_report_verification_fixed_paths_verified`, rewritten report file-entry role/SHA256/byte-size parity, deterministic source-report-to-rewritten-report path-rewrite parity through `archive_report_source_rewrite_verified`, archived verifier JSON archive-path/source-report SHA256/size metadata, required report presence, source-verification manifest metadata and archived verifier JSON when requested, archive-relative replay-critical paths inside embedded reports plus their expected manifest roles, `requested_output_file` path binding when present, and replays the embedded confusion and correction reports from extracted archive bytes. Archive creation clears `requested_output_file` when a failed/suppressed correction replay did not package an output member, so archived reports do not retain operator-local requested-output paths. This is still synthetic/testable OCR-safe evidence only; it does not certify real camera/photo, physical print-scan, or backend-specific OCR transfer.
Source-verification schema binding is exposed separately as `source_report_verification_schemas_verified`; it fails closed if report-level or archived source-verifier JSON drifts to the wrong verifier schema, even when the member digest metadata is self-consistent. Source-report role ownership is exposed as `source_report_archive_roles_verified`; it fails closed if the archived original source-report file record or the report-level `source_report_archive.role` metadata is owned by the wrong expected role. Source-report member state is exposed as `source_report_archive_member_state_verified`; it fails closed if the archived original source-report JSON has the wrong schema or success-state drift, even when digest metadata is recomputed. Source-verification member state is exposed as `source_report_verification_member_state_verified`; it fails closed if the archived source-verifier JSON has the wrong schema, malformed state fields, or success/failure-count drift, even when archive-entry digest metadata is recomputed. Source-verification role ownership is exposed as `source_report_verification_roles_verified`; it fails closed if the archived source-verifier file record or report-level `source_verification.role` metadata is owned by the wrong expected role. Source-verifier report binding is exposed as `source_report_verification_report_binding_verified`; it fails closed if manifest-level or archived source-verifier `report_sha256` or archive-relative `report_file` points away from the archived source report being verified. Source-verifier archive-entry file-record/member drift, archived source-verifier JSON `report_sha256`, `report_file`, `archive_path`, or `source_report_archive_*` binding drift, source-verification summary count/role drift, ordinary manifest summary drift (`summary.report_count`, `summary.report_roles`, `summary.file_count`, `summary.total_size_bytes`, and `summary.roles`), and rewritten-report manifest/member success-state drift also fail aggregate `archive_report_metadata_verified`, while the narrower source-verifier, summary, and state gates remain available for diagnosis. Regenerated OCR-safe archives also stamp each archived rewritten report JSON member with its expected fixed archive role; drift fails `archive_report_roles_verified` with `archive_report_member_role_mismatch` even when digest metadata is recomputed.

### 4.6 Certify OCR-Only Backends

OCR-only certification is separate from the production sidecar path. It must be requested explicitly, must use a named OCR backend, and must run on pages exported without binary sidecar boxes:

```powershell
python .\soenc.py transport certify -o .\ocr_only_cert --backend tesseract --no-sidecar --payload-size 64 --iterations-per-size 1 --require-ocr-only-backend --ocr-only-required-success-rate 0.99
```

Use `--backend tesseract`, `--backend easyocr`, or `--backend external --ocr-provider-cmd ...`. Reports record an `ocr_only_certification` block, per-case `ocr_only_evidence`, per-backend success rates, and fail closed with `ocr_only_evidence_missing` if a sidecar is present or the selected backend is not the requested OCR backend. OCR-only evidence is backend-specific and measured-condition-specific. It does not certify generic OCR fallback, camera transfer, physical print-scan transfer, or `reliable-airgap-v1` production readiness.

For operator-supplied OCR-only capture sets, stage a sidecar-free kit instead of editing manifests by hand:

```powershell
python .\soenc.py transport prepare-capture-corpus -o .\ocr_only_capture --classification lab --capture-medium print-scan --ocr-only-backend tesseract --payload-size 64 --iterations-per-size 1 --seed 20260527 --chunk-chars 24 --lines-per-page 8 --redundancy-copies 2 --parity-group-size 4
```

This writes non-production profile `ocr-only-backend-v1`, records `metadata.ocr_only_backend`, and exports pages whose manifests explicitly have `sidecar_enabled=false`. After captures are attached, preflight the sidecar-free/backend gate before running OCR recovery:

```powershell
python .\soenc.py transport validate-capture-corpus --capture-corpus-file .\ocr_only_capture\capture_corpus.json --profile ocr-only-backend-v1 --backend tesseract --require-captures --require-distinct-capture-images --capture-attachment-report-file .\ocr_only_capture\transport_capture_attachment_report.json --require-capture-attachment-report --capture-required-classification lab --require-ocr-only-backend
```

The validation report proves only that the corpus is ready for a backend-specific OCR-only measurement. It does not run OCR recovery and does not certify generic OCR fallback.

### 4.7 Attach Operator Capture Corpus Evidence

For a single encrypted-text operator trial that matches a manual phone-photo workflow, use the dedicated helper script. It encrypts the supplied text with the platform encryption helper, exports QR/transport pages, stages camera capture folders, and later runs attach, validate, certify, archive, verify, executable replay, certification status, and final plaintext SHA256 verification after the operator drops photos into the prepared capture directory:

```powershell
python .\scripts\real_capture_text_transport.py prepare --text "enc2sop real capture trial" --work-dir .\real_capture_text_trial --label phone-trial-001 --capture-kind camera-photo --operator example-operator --device "phone-camera" --captured-at-utc 2026-06-01T00:00:00Z
```

Print or display the generated pages from `.\real_capture_text_trial\export\pages`, photograph them on the target device, then copy the resulting photo files into the `capture_dir` printed by `prepare`. After that, run:

```powershell
python .\scripts\real_capture_text_transport.py certify --work-dir .\real_capture_text_trial --claim none
```

`--claim none` is a measured round-trip harness, not a production medium claim. It proves that this prepared text payload, generated transport pages, supplied images, archive, replay, and decrypted plaintext SHA256 agree. For a production physical print-scan claim, run `certify --claim physical-print-scan` with scanner/printer/DPI provenance and byte-distinct scan images. For a real camera perspective-correction claim, run `certify --claim real-camera-perspective-correction` with raw camera photos, corrected recovery images, and the strict real-camera gate. Copying generated page PNGs into `captures/*` is only a smoke test and must not be described as real camera/photo or physical print-scan evidence.

If no real capture corpus exists yet, prepare a physical/lab capture kit first:

```powershell
python .\soenc.py transport prepare-capture-corpus -o .\capture_kit --classification lab --capture-medium print-scan --payload-size 64 --payload-size 257 --iterations-per-size 1 --seed 20260526 --chunk-chars 24 --lines-per-page 8 --redundancy-copies 2 --parity-group-size 4 --capture-metadata printer=example-printer --capture-metadata scanner=example-flatbed --capture-metadata dpi=300
```

This writes `capture_kit_manifest.json`, `capture_corpus.json`, generated pages under `exports/*/pages`, empty drop directories under `captures/*`, `instructions/NEXT_STEPS.md`, `instructions/operator_capture_metadata_manifest_template.json`, and `instructions/operator_return_manifest_template.json`. Fill the metadata template with the real session, operator, capture timestamp, and scanner/camera/printer values before passing it to `ingest-capture-corpus` or `certify-capture-evidence` with `--capture-metadata-manifest-file`. If the operator returns a ZIP, rename the return template to `operator_return_manifest.json` at the ZIP root so extraction can bind the return package to the prepared corpus SHA256 and, when filled, the kit-manifest SHA256. The template now includes a required `capture_file_inventory`; replace the placeholders with every returned scan/photo package path plus its SHA256 and byte size so extraction can reject missing, extra, or drifted capture files. The kit and templates are a replay contract only. They are not certification evidence until real photos/scans are placed in the matching `captures/*` directories or ingested from an external return folder and `certify --capture-corpus-file ... --capture-corpus-only` produces a passing `transport_reliability_report.json`.

For real camera perspective-correction evidence, stage raw-photo directories up front:

```powershell
python .\soenc.py transport prepare-capture-corpus -o .\camera_capture --classification real --capture-medium camera-photo --include-raw-capture-dirs --perspective-correction-method "operator-supplied homography correction" --payload-size 64 --iterations-per-size 1 --seed 20260527 --chunk-chars 24 --lines-per-page 8 --redundancy-copies 2 --parity-group-size 4
```

This adds `captures\CASE__raw` directories and writes each case's `raw_image_paths` plus `perspective_correction` metadata into `capture_corpus.json`. Put uncorrected camera photos in `captures\CASE__raw` and the corrected recovery images in the matching `captures\CASE` directory.

If the operator has raw camera photos but has not produced corrected images yet, materialize them through the capture contract before attachment:

```powershell
python .\soenc.py transport correct-capture-perspective --capture-corpus-file .\camera_capture\capture_corpus.json --kit-manifest-file .\camera_capture\capture_kit_manifest.json -o .\camera_capture\corrected --method "operator-supplied homography correction" --mode four-point --require-raw-captures
```

`correct-capture-perspective` writes `transport_capture_perspective_correction_report.json` using schema `enc2sop-transport-capture-perspective-correction-report/v1`, writes corrected images into the corpus `image_path`, and records raw/corrected/reference image SHA256 values. `--mode copy` is for externally corrected images already staged as raw inputs, `--mode normalize` applies EXIF transpose, and `--mode four-point` uses per-case `perspective_correction.source_corners` (`[[x,y], ...]` in top-left, top-right, bottom-right, bottom-left order). This is preparation evidence only. It does not run recovery and does not certify real camera transfer; still run `attach-capture-corpus --require-raw-captures`, `validate-capture-corpus --require-real-camera-perspective-correction`, `certify --require-real-camera-perspective-correction`, archive verification, and `certification-status --require-certified-claim real-camera-perspective-correction`.

If a lab team or operator hands back an external folder tree instead of filling the prepared kit directories directly, ingest it into the corpus before attachment. The capture root must contain one subdirectory per case label from `capture_corpus.json`; an optional raw root can contain matching raw-photo subdirectories for camera evidence:

```powershell
python .\soenc.py transport ingest-capture-corpus --capture-corpus-file .\capture_kit\capture_corpus.json --capture-root .\lab_scans --kit-manifest-file .\capture_kit\capture_kit_manifest.json --capture-medium print-scan --capture-metadata scanner=example-flatbed --capture-metadata dpi=300 --require-captures
```

For real camera runs, add `--raw-capture-root .\raw_photos --require-raw-captures --classification real --capture-medium camera-photo`. For multi-case lab returns, fill the generated `instructions\operator_capture_metadata_manifest_template.json` and pass it with `--capture-metadata-manifest-file` instead of repeating many `--capture-metadata` flags. The metadata manifest schema is `enc2sop-transport-capture-metadata-manifest/v1` and can contain `capture_metadata_defaults` plus per-case `cases[].label` and `cases[].capture_metadata`; ingestion fails closed on manifest labels that do not match the prepared corpus unless `--allow-unmatched-labels` is used. `ingest-capture-corpus` writes `transport_capture_corpus_ingestion_report.json` (`enc2sop-transport-capture-corpus-ingestion-report/v1`), updates `capture_corpus.json` case `image_path`, `raw_image_paths`, and `capture_metadata`, records per-file SHA256/size bindings, and refreshes the kit manifest. It is still not recovery certification; run `attach-capture-corpus`, `validate-capture-corpus`, and the gated certification/archive/status chain next.

If the lab returns a ZIP package instead of an extracted folder tree, the one-command pipeline can safely extract it before ingestion. The ZIP should contain `captures/<case-label>/...`, optional `raw_captures/<case-label>/...` for camera evidence, optionally `operator_capture_metadata_manifest.json`, and preferably `operator_return_manifest.json` at the package root:

```powershell
python .\soenc.py transport package-capture-return --capture-corpus-file .\capture_kit\capture_corpus.json --capture-root .\lab_scans -o .\operator_return_pkg --kit-manifest-file .\capture_kit\capture_kit_manifest.json --capture-metadata-manifest-file .\operator_capture_metadata_manifest.json --return-session-id example-session-001 --operator example-operator --require-capture-provenance
```

This writes `operator_return.zip`, `operator_return_manifest.json`, `operator_capture_metadata_manifest.json`, and `transport_capture_return_package_report.json` (`enc2sop-transport-capture-return-package/v1`). It computes the exact inventory SHA256 and byte sizes from the files on disk, so operators do not need to hand-fill those values. For camera packages, add `--raw-capture-root .\raw_photos --require-raw-captures`. Add `--require-capture-provenance` for any lab/real handoff that will later support a print-scan or camera claim; package creation then fails closed unless the packaged metadata manifest provides session, operator, timestamp, and scanner/camera/printer identity for every case. Package creation is still handoff integrity evidence only; it does not certify print-scan, camera, or OCR-only support.

```powershell
python .\soenc.py transport certify-capture-evidence --capture-corpus-file .\capture_kit\capture_corpus.json --capture-return-package-file .\operator_return_pkg\operator_return.zip --capture-return-package-report-file .\operator_return_pkg\transport_capture_return_package_report.json -o .\capture_pipeline --kit-manifest-file .\capture_kit\capture_kit_manifest.json --profile reliable-airgap-v1 --backend sidecar --capture-medium print-scan --require-capture-return-manifest --require-capture-return-file-inventory --require-capture-return-package-report --require-capture-provenance --require-physical-print-scan --capture-required-classification lab --require-certified-claim physical-print-scan
```

This writes `return_package\transport_capture_return_package_extraction_report.json` with schema `enc2sop-transport-capture-return-package-extraction/v1`, rejects unsafe ZIP members, records extracted file SHA256 values, validates the optional `enc2sop-transport-capture-return-manifest/v1` corpus/kit bindings and case labels, and validates manifest-declared capture/raw file inventory when present or required. For launch/lab handoffs, add `--require-capture-return-manifest`, `--require-capture-return-file-inventory`, and `--require-capture-return-package-report` so ingestion does not start unless the ZIP contains a validated return manifest, exact image inventory, and a matching package-assembly report. A required inventory fails closed when a listed image is missing, its SHA256 or size differs from ZIP bytes, a listed path is outside the expected case directory, or the ZIP includes an unlisted capture image. ZIP extraction and return-manifest validation are handoff evidence only; they do not certify print-scan, camera, or OCR-only support without the later measured claim gates.

After the operator places photos or scans into the `captures/*` directories, refresh the capture corpus attachment record before certification:

```powershell
python .\soenc.py transport attach-capture-corpus --capture-corpus-file .\capture_kit\capture_corpus.json --kit-manifest-file .\capture_kit\capture_kit_manifest.json --require-captures --require-distinct-capture-images
```

This writes `transport_capture_attachment_report.json`, updates `capture_corpus.json` with per-case `attached_capture_images` SHA256 records, and refreshes the kit manifest's operator-capture summary. It is still not recovery certification; it only proves which files were attached to the corpus before the `certify` run.

For staged camera perspective kits, add `--require-raw-captures` to fail closed until every case has raw uncorrected camera photos attached:

```powershell
python .\soenc.py transport attach-capture-corpus --capture-corpus-file .\camera_capture\capture_corpus.json --kit-manifest-file .\camera_capture\capture_kit_manifest.json --require-captures --require-raw-captures --require-distinct-capture-images
```

Before spending time on a certification run, validate the corpus and exact gates you intend to claim:

```powershell
python .\soenc.py transport validate-capture-corpus --capture-corpus-file .\capture_kit\capture_corpus.json --output-file .\capture_kit\transport_capture_validation_report.json --profile reliable-airgap-v1 --backend sidecar --require-captures --require-distinct-capture-images --capture-attachment-report-file .\capture_kit\transport_capture_attachment_report.json --require-capture-attachment-report --require-capture-provenance --capture-required-classification lab --require-physical-print-scan
```

This writes `enc2sop-transport-capture-corpus-validation/v1`. It checks corpus structure, profile compliance, attached image SHA256s, distinctness from generated references, attachment-report lineage, optional capture provenance, and optional print-scan or real-camera perspective gates. It does not run recovery and does not certify a medium; use it as a preflight to find missing captures, raw photos, metadata, provenance, or lineage before `certify`.

When a real or lab capture set exists, attach it with a capture corpus manifest instead of changing code:

```powershell
python .\soenc.py transport certify -o .\transport_cert --profile reliable-airgap-v1 --backend sidecar --redundancy-copies 2 --parity-group-size 4 --capture-corpus-file .\capture_kit\capture_corpus.json --capture-corpus-only
```

When the report will support a real or lab capture claim, add explicit gates:

```powershell
python .\soenc.py transport certify -o .\transport_cert --profile reliable-airgap-v1 --backend sidecar --redundancy-copies 2 --parity-group-size 4 --capture-corpus-file .\capture_kit\capture_corpus.json --capture-corpus-only --capture-required-classification lab --capture-required-success-rate 1.0 --require-distinct-capture-images --require-capture-attachment-report --require-capture-provenance
```

For a physical print-scan claim, set the corpus or case `capture_medium` to `print-scan`, record printer/scanner/dpi metadata, and require the print-scan gate:

```powershell
python .\soenc.py transport certify -o .\transport_cert --profile reliable-airgap-v1 --backend sidecar --redundancy-copies 2 --parity-group-size 4 --capture-corpus-file .\capture_kit\capture_corpus.json --capture-corpus-only --capture-required-classification lab --capture-required-success-rate 1.0 --require-distinct-capture-images --require-capture-attachment-report --require-capture-provenance --require-physical-print-scan
```

For a real camera perspective-correction claim, keep the raw camera photos and the corrected images as separate artifacts. The corrected images go in `image_path` because they are the images used for recovery; the uncorrected photos go in `raw_image_paths`. `attach-capture-corpus --require-raw-captures` proves the raw-photo files are present and hash-bound; `certify --require-real-camera-perspective-correction` proves the measured recovery path and strict camera evidence gate. Then require the camera gate:

```powershell
python .\soenc.py transport certify -o .\transport_cert --profile reliable-airgap-v1 --backend sidecar --redundancy-copies 2 --parity-group-size 4 --capture-corpus-file .\camera_capture\capture_corpus.json --capture-corpus-only --capture-required-classification real --capture-required-success-rate 1.0 --require-distinct-capture-images --require-capture-attachment-report --require-capture-provenance --require-real-camera-perspective-correction
```

For an OCR-only backend claim, use a sidecar-free kit and require the OCR-only backend gate. Do not add `--require-profile-certified`; `ocr-only-backend-v1` is not a production airgap profile:

```powershell
python .\soenc.py transport certify -o .\ocr_only_cert --profile ocr-only-backend-v1 --backend tesseract --redundancy-copies 2 --parity-group-size 4 --capture-corpus-file .\ocr_only_capture\capture_corpus.json --capture-corpus-only --capture-required-classification lab --capture-required-success-rate 0.99 --require-distinct-capture-images --require-capture-attachment-report --require-ocr-only-backend
```

After a certification run passes, package the replay evidence:

```powershell
python .\soenc.py transport archive-evidence --report-file .\transport_cert\transport_reliability_report.json -o .\transport_evidence_archive --require-successful-report --require-profile-certified --require-capture-attachment-report
```

Verify the archive before handoff or audit replay:

```powershell
python .\soenc.py transport verify-evidence-archive --archive-file .\transport_evidence_archive\transport_capture_evidence_archive.zip --manifest-file .\transport_evidence_archive\transport_capture_evidence_archive_manifest.json --require-successful-report --require-profile-certified --require-capture-attachment-report
```

Rerun recovery from the archived bytes when an auditor or release checklist needs executable replay, not only ZIP integrity:

```powershell
python .\soenc.py transport replay-evidence-archive --archive-file .\transport_evidence_archive\transport_capture_evidence_archive.zip --manifest-file .\transport_evidence_archive\transport_capture_evidence_archive_manifest.json -o .\transport_evidence_replay --require-successful-report --require-profile-certified --require-capture-attachment-report
```

For an operator corpus that is already populated with real/lab captures, the same gated chain can be run as one command:

```powershell
python .\soenc.py transport certify-capture-evidence --capture-corpus-file .\capture_kit\capture_corpus.json -o .\capture_pipeline --profile reliable-airgap-v1 --backend sidecar --capture-required-classification lab --require-capture-provenance --require-physical-print-scan --require-certified-claim physical-print-scan
```

If the operator returns a separate external folder tree, the same pipeline can ingest it before attachment and certification:

```powershell
python .\soenc.py transport certify-capture-evidence --capture-corpus-file .\capture_kit\capture_corpus.json --capture-root .\lab_scans -o .\capture_pipeline --kit-manifest-file .\capture_kit\capture_kit_manifest.json --profile reliable-airgap-v1 --backend sidecar --capture-medium print-scan --capture-metadata scanner=example-flatbed --capture-metadata dpi=300 --capture-metadata capture_session_id=example-session-001 --capture-metadata operator=example-operator --capture-metadata captured_at_utc=2026-05-28T00:00:00Z --capture-required-classification lab --require-capture-provenance --require-physical-print-scan --require-certified-claim physical-print-scan
```

For camera runs, add `--raw-capture-root .\raw_photos --require-raw-captures --capture-medium camera-photo`. For real/lab claim evidence, also add `--require-capture-provenance` and capture metadata such as `capture_session_id`, `operator`, `captured_at_utc`, and the scanner/camera/printer device. The pipeline then writes `ingest/transport_capture_corpus_ingestion_report.json` before the attachment report and fails closed before attachment if required capture or raw-photo folders are missing. This lets a lab/operator hand back external folders without JSON hand-editing, but it is still an orchestrator only: the physical print-scan, real camera, or OCR-only claim is usable only when the measured report and `certification-status` claim gate certify that exact claim.

This writes `transport_capture_certification_pipeline_report.json` (`enc2sop-transport-capture-certification-pipeline/v1`) plus optional ingestion, attach, validation, certification, archive, verification, replay, and status artifacts. The pipeline fails closed before certification status if ingestion, attachment, validation, recovery certification, archive packaging, archive verification, or executable archive replay fails.

This writes `transport_capture_evidence_archive.zip` plus `transport_capture_evidence_archive_manifest.json` (`enc2sop-transport-capture-evidence-archive/v1`). The archive manifest records SHA256/size/path metadata for the transport report, capture corpus, attachment report, payload, manifest, captured images, raw images, reference images, and recovered outputs when present. Add the exact archive creation gate for the claim being packaged: `--require-physical-print-scan`, `--require-real-camera-perspective-correction`, or `--require-ocr-only-backend`. Archive creation then fails closed unless the input report required and passed that same gate. `verify-evidence-archive` emits `enc2sop-transport-capture-evidence-archive-verification/v1` and fails closed on embedded/external manifest drift, unsafe or undeclared ZIP members, missing archive members, per-file digest/size mismatch, schema mismatch, requested gate mismatch, or certification-claim snapshot drift. `replay-evidence-archive` emits `enc2sop-transport-capture-evidence-archive-replay/v1`, extracts the ZIP, rewrites archived corpus paths to the extracted files, reruns recovery for the archived capture corpus, and compares replayed case success/failure reasons and payload/restored digests to the archived report. These commands preserve replayability only; they do not broaden the certification claim beyond the included `transport_reliability_report.json`.

Certification reports, archive manifests, and archive verification reports include `certification_claims` (`enc2sop-transport-certification-claims/v1`). Treat each claim independently: `generated-page-sidecar`, `generated-page-synthetic-stress`, `physical-print-scan`, `real-camera-perspective-correction`, and `backend-specific-ocr-only` are usable only when that claim has `certified=true`. A passing generated-page stress report is still synthetic-stress evidence, not real camera or physical scan evidence. A passing `lab` print-scan report is lab-scoped and does not certify other scanner/printer combinations.

Create an operator-facing certification status artifact before product or launch review:

```powershell
python .\soenc.py transport certification-status --report-file .\transport_cert\transport_reliability_report.json --output-file .\transport_cert\transport_certification_status.json
```

For archived evidence, summarize only after verification:

```powershell
python .\soenc.py transport certification-status --archive-file .\transport_evidence_archive\transport_capture_evidence_archive.zip --manifest-file .\transport_evidence_archive\transport_capture_evidence_archive_manifest.json --verify-archive --output-file .\transport_evidence_archive\transport_certification_status.json
```

This writes `enc2sop-transport-certification-status/v1`. It extracts the certified/uncertified matrix, source SHA256, profile state, evidence level, missing gates, and recommended next evidence steps from the measured report or verified archive. It is a launch-readable summary only; it does not broaden any claim beyond the underlying `certification_claims`.

When product copy or a release checklist depends on a specific transport claim, make the status command fail closed:

```powershell
python .\soenc.py transport certification-status --archive-file .\transport_evidence_archive\transport_capture_evidence_archive.zip --manifest-file .\transport_evidence_archive\transport_capture_evidence_archive_manifest.json --verify-archive --require-certified-claim physical-print-scan --output-file .\transport_evidence_archive\transport_certification_status.json
```

Repeat `--require-certified-claim` for every claim being made. The status artifact records `claim_gate.required_certified_claims`, `claim_gate.passed`, and `claim_gate.missing_required_certified_claims`; the CLI exits non-zero if any requested claim is not already certified by the measured report or verified archive.

`capture_corpus.json` uses schema `enc2sop-transport-capture-corpus/v1`:

```json
{
  "schema": "enc2sop-transport-capture-corpus/v1",
  "classification": "lab",
  "capture_medium": "print-scan",
  "metadata": {
    "printer": "example-printer",
    "scanner": "example-flatbed",
    "dpi": 300
  },
  "cases": [
    {
      "label": "flatbed-300dpi-page-set-001",
      "capture_medium": "print-scan",
      "manifest_path": ".\\exported\\PAYLOAD.manifest.json",
      "payload_path": ".\\payload.bin",
      "image_path": ".\\captures\\flatbed-300dpi-page-set-001",
      "raw_image_paths": ".\\camera_raw\\flatbed-300dpi-page-set-001",
      "reference_image_paths": [
        ".\\exported\\pages\\page_0001.png"
      ],
      "capture_metadata": {
        "printer": "example-printer",
        "scanner": "example-flatbed",
        "dpi": 300,
        "capture_session_id": "flatbed-session-001",
        "operator": "example-operator",
        "captured_at_utc": "2026-05-28T00:00:00Z",
        "lighting": "office"
      },
      "perspective_correction": {
        "applied": true,
        "method": "operator-supplied homography correction",
        "tool": "example correction tool",
        "source_corners": [[10, 12], [990, 18], [982, 1410], [14, 1398]]
      }
    }
  ]
}
```

Allowed corpus classifications are `real`, `lab`, `synthetic`, and `stress-only`. Allowed capture media are `unspecified`, `camera-photo`, `print-scan`, and `mixed`. The report records each case label, source image SHA256 values, attached image SHA256 values, optional reference image SHA256 values, optional raw camera image SHA256 values, capture metadata, backend, success/failure reason, capture-medium counts, and per-classification success rate. Under `reliable-airgap-v1`, attached captures also fail closed unless the manifest proves sidecar layout metadata, line CRC, compact page/hash metadata, manifest-guided indexing, payload SHA256 binding, and redundancy or parity. `--require-distinct-capture-images` additionally fails closed with `capture_reference_not_distinct` when attached captures are byte-identical to generated reference pages; use it for physical/lab capture claims so fixture-copy contract tests are not mistaken for scanner/camera evidence. `--require-capture-attachment-report` fails closed with `capture_attachment_report_mismatch` unless the current capture, raw-photo, and reference image SHA256/size/path records match `transport_capture_attachment_report.json` from `attach-capture-corpus`; use it after physical files are attached so certification proves it measured the same bound corpus. `--require-capture-provenance` fails closed with `capture_provenance_missing` unless each lab/real case declares a capture medium and records session, operator, timestamp, and capture-device metadata such as `capture_session_id`, `operator`, `captured_at_utc`, and `scanner` or `camera`. `attach-capture-corpus --require-raw-captures` fails closed with `raw_capture_images_missing` until every staged camera case has at least one raw photo in `raw_image_paths`. `--require-physical-print-scan` additionally fails closed with `capture_print_scan_evidence_missing` unless every supplied capture case is classified `lab` or `real`, declares `capture_medium=print-scan`, includes generated `reference_image_paths`, includes byte-distinct scan images in `image_path`, and records printer/scanner/dpi metadata. `--require-real-camera-perspective-correction` additionally fails closed with `capture_perspective_evidence_missing` unless every supplied capture case is classified `real`, includes raw camera photos, includes perspective-corrected recovery images, declares `perspective_correction.applied=true` plus a correction method, and proves raw/corrected/reference image sets are byte-distinct. Synthetic `perspective-skew-lite` reports do not satisfy this real camera gate.

Capture evidence certifies only the declared corpus classification, capture medium, and capture conditions. A passing `lab` print-scan corpus does not certify real camera transfer or other scanner/printer combinations. A passing `real` corpus certifies only the measured devices, scanners, printers, cameras, OCR backend, and operator conditions represented by that corpus. If the claim is OCR-only, also use `--require-ocr-only-backend` with a non-sidecar backend and sidecar-disabled captured/exported pages.

## 5. Backend Notes

1. `sidecar` is preferred for self-exported pages.
2. `tesseract` and `easyocr` are optional OCR backends.
3. `external` backend allows custom OCR integration through command templates.
4. Mainline platform commands remain operational even when OCR stacks are absent.
5. Use `certify --profile reliable-airgap-v1 --backend sidecar` for the current reliable generated-page evidence path.
6. Use `certify --require-ocr-only-backend --backend tesseract|easyocr|external --no-sidecar` only for backend-specific OCR-only measurements; those reports are not production airgap profile evidence.

## 6. Manifest-Less Recovery

Manifest-less flows are supported for embedded-metadata pages, but manifest-guided flows are preferred when available for stronger validation and diagnostics.

## 7. When To Use Transport

Use transport plugin only when you need airgap transfer or OCR-based recovery workflows. For core product delivery, use mainline `soenc protect/build/verify/package`.
