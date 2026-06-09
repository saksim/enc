"""Transport CLI/parser and output helpers extracted from qrcode_helper."""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional


_UNSET = object()

from . import certify as _transport_certify
from . import protocol


EXPERIMENTAL_EVIDENCE_COMMANDS = frozenset(
    {
        "certify",
        "certify-ocr-confusion",
        "verify-ocr-confusion",
        "archive-ocr-safe-evidence",
        "verify-ocr-safe-evidence-archive",
        "prepare-capture-corpus",
        "attach-capture-corpus",
        "package-capture-return",
        "ingest-capture-corpus",
        "correct-capture-perspective",
        "validate-capture-corpus",
        "certify-capture-evidence",
        "archive-evidence",
        "verify-evidence-archive",
        "replay-evidence-archive",
        "certification-status",
    }
)

EXPERIMENTAL_EVIDENCE_NOTICE = (
    "EXPERIMENTAL evidence tooling retained for legacy certification/archive/status "
    "workflows. It is not part of the current cross-media encrypted user path; "
    "use `soenc cm send` and `soenc cm receive` for normal operation."
)


def print_json(data: Dict[str, object]) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def save_json(path: str, data: Dict[str, object]) -> str:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    return str(out)


def save_missing_chunks(path: str, records: List[Dict[str, int]]) -> str:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    preferred = ["chunk_index", "page", "line", "copy", "priority"]
    extra = []
    for item in records:
        for key in item.keys():
            if key in preferred or key in extra:
                continue
            extra.append(key)
    columns = preferred + extra
    lines = [",".join(columns)]
    for item in records:
        row = [str(item.get(col, "")) for col in columns]
        lines.append(",".join(row))
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(out)


def _csv_escape(value: object) -> str:
    text = str(value if value is not None else "")
    if any(ch in text for ch in [",", '"', "\n", "\r"]):
        return '"' + text.replace('"', '""') + '"'
    return text


def save_corrections_template(path: str, records: List[Dict[str, object]]) -> str:
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    columns = [
        "page",
        "line",
        "raw_text",
        "normalized_text",
        "candidates",
        "status",
        "expected_crc",
        "actual_crc",
        "corrected_text",
    ]
    lines = [",".join(columns)]
    for item in records:
        candidates = item.get("candidates", [])
        if isinstance(candidates, list):
            candidates_value = "|".join(str(candidate) for candidate in candidates)
        else:
            candidates_value = str(candidates or "")
        row = []
        for column in columns:
            value = candidates_value if column == "candidates" else item.get(column, "")
            row.append(_csv_escape(value))
        lines.append(",".join(row))
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(out)


def parse_metadata_items(items: Optional[List[str]]) -> Dict[str, object]:
    metadata: Dict[str, object] = {}
    for raw in items or []:
        if "=" not in str(raw):
            raise ValueError("metadata items must use KEY=VALUE format: {}".format(raw))
        key, value = str(raw).split("=", 1)
        key = key.strip()
        if not key:
            raise ValueError("metadata item key must be non-empty")
        metadata[key] = value.strip()
    return metadata


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Airgap transport layer for encrypted small artifacts. Legacy OCR/sidecar "
            "commands remain available; certify/archive/status evidence commands are "
            "experimental and outside the current `soenc cm send/receive` main path."
        )
    )
    sub = parser.add_subparsers(dest="cmd")
    # Python 3.6 does not support add_subparsers(..., required=True)
    sub.required = True

    p_export = sub.add_parser("export", help="export artifact bytes to OCR package")
    p_export.add_argument(
        "-i",
        "--input-file",
        required=True,
        help="input artifact path; encrypt first if confidentiality matters",
    )
    p_export.add_argument("-o", "--output-dir", required=True, help="output package directory")
    p_export.add_argument("--artifact-id", default=None, help="optional artifact id")
    p_export.add_argument("--filename-prefix", default="page", help="output page prefix")
    p_export.add_argument("--max-compressed-kib", type=int, default=64)
    p_export.add_argument("--chunk-chars", type=int, default=40)
    p_export.add_argument("--lines-per-page", type=int, default=20)
    p_export.add_argument(
        "--font-size",
        type=int,
        default=44,
        help="target font size for rendered PNG pages (default fit mode: target)",
    )
    p_export.add_argument(
        "--font-max-size",
        type=int,
        default=132,
        help="upper bound used only when --font-fit-mode fit",
    )
    p_export.add_argument(
        "--font-fit-mode",
        choices=["target", "fit", "fixed"],
        default="target",
        help="target: keep --font-size unless overflow; fit: auto enlarge to max; fixed: strict fixed size",
    )
    p_export.add_argument(
        "--fixed-font-size",
        action="store_true",
        help="deprecated alias of --font-fit-mode fixed",
    )
    p_export.add_argument(
        "--metadata-level",
        choices=["compact", "none"],
        default="compact",
        help="page control metadata level: compact keeps @META/@CFG/@HS/@PAGECRC, none keeps data lines only",
    )
    p_export.add_argument(
        "--line-separator",
        choices=list(protocol.SUPPORTED_FIELD_SEPARATORS),
        default="|",
        help="field separator in exported data lines",
    )
    p_export.add_argument(
        "--line-index-mode",
        choices=["full", "chunk", "off"],
        default="full",
        help="full: P/L/C, chunk: C only, off: payload only (manifest required for recover/verify)",
    )
    p_export.add_argument(
        "--line-crc-mode",
        choices=["on", "off"],
        default="on",
        help="append per-line CRC suffix in transport lines",
    )
    p_export.add_argument(
        "--payload-alphabet-profile",
        choices=list(protocol.SUPPORTED_PAYLOAD_ALPHABET_PROFILES),
        default="safe-base32-v1",
        help="payload alphabet profile; ocr-safe-human-correctable-v1 avoids ambiguous glyphs",
    )
    p_export.add_argument(
        "--no-sidecar",
        action="store_true",
        help="disable rendering right-side sidecar blocks in PNG pages",
    )
    p_export.add_argument(
        "--redundancy-copies",
        type=int,
        default=1,
        help="repeat each chunk N copies for anti-loss transport (default 1)",
    )
    p_export.add_argument(
        "--no-interleave",
        action="store_true",
        help="disable interleaving chunk copies across pages",
    )
    p_export.add_argument(
        "--parity-group-size",
        type=int,
        default=0,
        help="add one parity chunk per N data chunks (0 disables, recommended 8)",
    )

    p_estimate = sub.add_parser("estimate", help="estimate export size, chunk count, and page count")
    p_estimate.add_argument("-i", "--input-file", required=True, help="input artifact path")
    p_estimate.add_argument("--max-compressed-kib", type=int, default=64)
    p_estimate.add_argument("--chunk-chars", type=int, default=40)
    p_estimate.add_argument("--lines-per-page", type=int, default=20)
    p_estimate.add_argument(
        "--redundancy-copies",
        type=int,
        default=1,
        help="repeat each chunk N copies for anti-loss transport (default 1)",
    )
    p_estimate.add_argument(
        "--no-interleave",
        action="store_true",
        help="disable interleaving chunk copies across pages",
    )
    p_estimate.add_argument(
        "--parity-group-size",
        type=int,
        default=0,
        help="add one parity chunk per N data chunks (0 disables, recommended 8)",
    )
    p_estimate.add_argument(
        "--payload-alphabet-profile",
        choices=list(protocol.SUPPORTED_PAYLOAD_ALPHABET_PROFILES),
        default="safe-base32-v1",
        help="payload alphabet profile for encoded size and parity planning",
    )

    p_recover = sub.add_parser("recover", help="recover artifact from OCR text")
    p_recover.add_argument(
        "-m",
        "--manifest",
        default=None,
        help="manifest json path; optional when OCR text contains embedded export metadata",
    )
    p_recover.add_argument("-t", "--ocr-input", required=True, help="ocr text file/dir")
    p_recover.add_argument("-o", "--output-file", required=True, help="recovered artifact path")
    p_recover.add_argument("--strict-payload-chars", action="store_true")
    p_recover.add_argument(
        "--apply-corrections-file",
        dest="corrections_file",
        default=None,
        help="filled OCR-safe corrections_template.csv to replay before final sha verification",
    )

    p_verify = sub.add_parser("verify", help="verify OCR text against manifest")
    p_verify.add_argument(
        "-m",
        "--manifest",
        default=None,
        help="manifest json path; optional when OCR text contains embedded export metadata",
    )
    p_verify.add_argument("-t", "--ocr-input", required=True, help="ocr text file/dir")
    p_verify.add_argument("--strict-payload-chars", action="store_true")
    p_verify.add_argument(
        "--apply-corrections-file",
        dest="corrections_file",
        default=None,
        help="filled OCR-safe corrections_template.csv to replay before final sha verification",
    )

    p_replay_corrections = sub.add_parser(
        "replay-corrections",
        help="replay a filled OCR-safe corrections_template.csv and write a SHA-verified report",
    )
    p_replay_corrections.add_argument(
        "-m",
        "--manifest",
        required=True,
        help="manifest json path from an ocr-safe-human-correctable-v1 export",
    )
    p_replay_corrections.add_argument(
        "-t",
        "--ocr-input",
        required=True,
        help="OCR text file/dir to replay corrections against",
    )
    p_replay_corrections.add_argument(
        "--apply-corrections-file",
        dest="corrections_file",
        required=True,
        help="filled OCR-safe corrections_template.csv",
    )
    p_replay_corrections.add_argument(
        "-o",
        "--output-file",
        default=None,
        help="optional recovered artifact output path; written only after final SHA verification",
    )
    p_replay_corrections.add_argument(
        "--report-file",
        default=None,
        help="optional correction replay report JSON path",
    )
    p_replay_corrections.add_argument(
        "--emit-corrections-template",
        default=None,
        help=(
            "optional path for refreshed unresolved correction rows; defaults beside "
            "--report-file on failed replay"
        ),
    )
    p_replay_corrections.add_argument("--strict-payload-chars", action="store_true")

    p_verify_correction_replay = sub.add_parser(
        "verify-correction-replay",
        help="verify a saved OCR-safe correction replay report and referenced artifacts",
    )
    p_verify_correction_replay.add_argument(
        "--report-file",
        required=True,
        help="transport_ocr_correction_replay_report.json to verify",
    )
    p_verify_correction_replay.add_argument(
        "--output-file",
        default=None,
        help="optional correction replay verification report JSON path",
    )
    p_verify_correction_replay.add_argument(
        "--allow-failed-report",
        action="store_true",
        help="do not require the source correction replay report to have success=true",
    )

    p_certify_ocr_confusion = sub.add_parser(
        "certify-ocr-confusion",
        help=(
            "write replayable synthetic OCR confusion evidence for "
            "ocr-safe-human-correctable-v1"
        ),
    )
    p_certify_ocr_confusion.add_argument(
        "-o",
        "--output-dir",
        required=True,
        help="output directory for synthetic OCR confusion evidence",
    )
    p_certify_ocr_confusion.add_argument(
        "--report-file",
        default=None,
        help=(
            "optional report path; defaults to "
            "<output-dir>/synthetic_ocr_confusion_report.json"
        ),
    )
    p_certify_ocr_confusion.add_argument(
        "--payload-size",
        type=int,
        default=512,
        help="deterministic synthetic payload size in bytes",
    )
    p_certify_ocr_confusion.add_argument("--chunk-chars", type=int, default=18)
    p_certify_ocr_confusion.add_argument("--lines-per-page", type=int, default=5)
    p_certify_ocr_confusion.add_argument(
        "--payload-alphabet-profile",
        choices=list(protocol.SUPPORTED_PAYLOAD_ALPHABET_PROFILES),
        default=protocol.OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
        help=(
            "must remain ocr-safe-human-correctable-v1 for the synthetic "
            "confusion suite"
        ),
    )
    p_certify_ocr_confusion.add_argument(
        "--no-sidecar",
        action="store_true",
        help="disable rendering sidecar blocks in the synthetic export",
    )
    p_certify_ocr_confusion.add_argument(
        "--render-sidecar",
        dest="no_sidecar",
        action="store_false",
        help="render sidecar blocks in the synthetic export for comparison only",
    )
    p_certify_ocr_confusion.set_defaults(no_sidecar=True)
    p_certify_ocr_confusion.add_argument("--seed", type=int, default=20260530)
    p_certify_ocr_confusion.add_argument(
        "--redundancy-copies",
        type=int,
        default=2,
        help="repeat each chunk N copies in the synthetic export",
    )
    p_certify_ocr_confusion.add_argument(
        "--parity-group-size",
        type=int,
        default=4,
        help="add one parity chunk per N data chunks in the synthetic export",
    )
    p_certify_ocr_confusion.add_argument(
        "--filename-prefix",
        default="ocr_confusion_page",
        help="output page filename prefix for the generated synthetic package",
    )

    p_verify_ocr_confusion = sub.add_parser(
        "verify-ocr-confusion",
        help="verify a saved synthetic OCR-safe confusion report and referenced artifacts",
    )
    p_verify_ocr_confusion.add_argument(
        "--report-file",
        required=True,
        help="synthetic_ocr_confusion_report.json to verify",
    )
    p_verify_ocr_confusion.add_argument(
        "--output-file",
        default=None,
        help="optional verification report JSON path",
    )
    p_verify_ocr_confusion.add_argument(
        "--allow-failed-report",
        action="store_true",
        help="do not require the source synthetic confusion report to have success=true",
    )

    p_archive_ocr_safe = sub.add_parser(
        "archive-ocr-safe-evidence",
        help="package OCR-safe synthetic/correction evidence into a replayable archive",
    )
    p_archive_ocr_safe.add_argument(
        "--archive-file",
        required=True,
        help="output OCR-safe evidence ZIP archive path",
    )
    p_archive_ocr_safe.add_argument(
        "--manifest-file",
        default=None,
        help="optional external archive manifest JSON path",
    )
    p_archive_ocr_safe.add_argument(
        "--confusion-report-file",
        default=None,
        help="synthetic_ocr_confusion_report.json to include",
    )
    p_archive_ocr_safe.add_argument(
        "--correction-replay-report-file",
        default=None,
        help="transport_ocr_correction_replay_report.json to include",
    )
    p_archive_ocr_safe.add_argument(
        "--require-confusion-report",
        action="store_true",
        help="fail unless a successful synthetic confusion report is included",
    )
    p_archive_ocr_safe.add_argument(
        "--require-correction-replay-report",
        action="store_true",
        help="fail unless a successful correction replay report is included",
    )
    p_archive_ocr_safe.add_argument(
        "--require-source-report-verification",
        action="store_true",
        help=(
            "fail unless included source reports verify replayably before archive "
            "creation"
        ),
    )

    p_verify_ocr_safe_archive = sub.add_parser(
        "verify-ocr-safe-evidence-archive",
        help="verify and replay an OCR-safe synthetic/correction evidence archive",
    )
    p_verify_ocr_safe_archive.add_argument(
        "--archive-file",
        required=True,
        help="OCR-safe evidence ZIP archive to verify",
    )
    p_verify_ocr_safe_archive.add_argument(
        "--manifest-file",
        default=None,
        help="optional external archive manifest JSON path",
    )
    p_verify_ocr_safe_archive.add_argument(
        "--output-file",
        default=None,
        help="optional archive verification report JSON path",
    )
    p_verify_ocr_safe_archive.add_argument(
        "--require-confusion-report",
        action="store_true",
        help="fail unless the archive contains a verified synthetic confusion report",
    )
    p_verify_ocr_safe_archive.add_argument(
        "--require-correction-replay-report",
        action="store_true",
        help="fail unless the archive contains a verified correction replay report",
    )
    p_verify_ocr_safe_archive.add_argument(
        "--require-source-report-verification",
        action="store_true",
        help=(
            "fail unless the archive manifest records successful pre-archive "
            "source report verification"
        ),
    )
    p_verify_ocr_safe_archive.add_argument(
        "--allow-failed-report",
        action="store_true",
        help="do not require included source reports to have success=true",
    )

    p_analyze = sub.add_parser("analyze", help="analyze OCR text quality and missing chunks")
    p_analyze.add_argument(
        "-m",
        "--manifest",
        default=None,
        help="manifest json path; optional when OCR text contains embedded export metadata",
    )
    p_analyze.add_argument("-t", "--ocr-input", required=True, help="ocr text file/dir")
    p_analyze.add_argument("--strict-payload-chars", action="store_true")
    p_analyze.add_argument("--max-list", type=int, default=200, help="max list size in output")
    p_analyze.add_argument("--save-report", default=None, help="optional analyze json output path")
    p_analyze.add_argument(
        "--emit-missing-file",
        default=None,
        help="optional csv output with chunk_index,page,line,copy,priority for recapture",
    )
    p_analyze.add_argument(
        "--emit-corrections-template",
        default=None,
        help="optional csv output for OCR-safe unresolved or multi-candidate correction rows",
    )
    p_analyze.add_argument(
        "--apply-corrections-file",
        dest="corrections_file",
        default=None,
        help="filled OCR-safe corrections_template.csv to replay during analysis",
    )

    p_ocr = sub.add_parser("ocr-extract", help="extract text from images with OCR backend")
    p_ocr.add_argument("-i", "--image-input", required=True, help="image file/dir")
    p_ocr.add_argument("-o", "--output-text", required=True, help="output text file path")
    p_ocr.add_argument(
        "-m",
        "--manifest",
        default=None,
        help="optional manifest to enable structured OCR on self-generated pages",
    )
    p_ocr.add_argument(
        "--backend",
        choices=["tesseract", "easyocr", "sidecar", "external", "auto"],
        default="tesseract",
    )
    p_ocr.add_argument("--lang", default="eng", help="ocr language")
    p_ocr.add_argument("--psm", type=int, default=6, help="tesseract psm mode")
    p_ocr.add_argument(
        "--ocr-provider-cmd",
        default=None,
        help=(
            "external OCR command template used by backend=external/auto; placeholders: "
            "{image_path} {image_name} {page_no} {lang} {psm} {manifest_path}"
        ),
    )
    p_ocr.add_argument(
        "--ocr-provider-timeout-sec",
        type=int,
        default=120,
        help="timeout seconds for one external OCR command call",
    )

    p_recover_images = sub.add_parser(
        "recover-images", help="ocr images then analyze+recover artifact in one command"
    )
    p_recover_images.add_argument(
        "-m",
        "--manifest",
        default=None,
        help="manifest json path; optional when page photos are from exports with embedded metadata",
    )
    p_recover_images.add_argument("-i", "--image-input", required=True, help="image file/dir")
    p_recover_images.add_argument("-o", "--output-file", required=True, help="recovered artifact path")
    p_recover_images.add_argument(
        "--backend",
        choices=["tesseract", "easyocr", "sidecar", "external", "auto"],
        default="auto",
    )
    p_recover_images.add_argument("--lang", default="eng", help="ocr language")
    p_recover_images.add_argument("--psm", type=int, default=6, help="tesseract psm mode")
    p_recover_images.add_argument(
        "--ocr-provider-cmd",
        default=None,
        help=(
            "external OCR command template used by backend=external/auto; placeholders: "
            "{image_path} {image_name} {page_no} {lang} {psm} {manifest_path}"
        ),
    )
    p_recover_images.add_argument(
        "--ocr-provider-timeout-sec",
        type=int,
        default=120,
        help="timeout seconds for one external OCR command call",
    )
    p_recover_images.add_argument("--strict-payload-chars", action="store_true")
    p_recover_images.add_argument(
        "--ocr-text-output", default=None, help="optional extracted OCR text output path"
    )
    p_recover_images.add_argument(
        "--save-analyze-report", default=None, help="optional analyze report json path"
    )
    p_recover_images.add_argument(
        "--emit-missing-file",
        default=None,
        help="optional csv output with chunk_index,page,line,copy,priority for recapture",
    )
    p_recover_images.add_argument(
        "--emit-corrections-template",
        default=None,
        help="optional csv output for OCR-safe unresolved or multi-candidate correction rows",
    )
    p_recover_images.add_argument(
        "--apply-corrections-file",
        dest="corrections_file",
        default=None,
        help="filled OCR-safe corrections_template.csv to replay before final sha verification",
    )
    p_recover_images.add_argument("--max-list", type=int, default=200, help="max list size in analyze")

    p_certify = sub.add_parser(
        "certify", help="generate replayable transport reliability evidence"
    )
    p_certify.add_argument("-o", "--output-dir", required=True, help="certification output directory")
    p_certify.add_argument(
        "--report-file",
        default=None,
        help="optional report path; defaults to <output-dir>/transport_reliability_report.json",
    )
    p_certify.add_argument(
        "--payload-size",
        dest="payload_sizes",
        action="append",
        type=int,
        default=None,
        help="payload size in bytes; repeat to build a deterministic corpus",
    )
    p_certify.add_argument("--iterations-per-size", type=int, default=1)
    p_certify.add_argument("--seed", type=int, default=1729)
    p_certify.add_argument(
        "--profile",
        choices=["digital-sidecar-v1", "reliable-airgap-v1", "ocr-only-backend-v1"],
        default=None,
        help="certification profile; reliable-airgap-v1 enforces production transport guardrails",
    )
    p_certify.add_argument(
        "--payload-alphabet-profile",
        choices=list(protocol.SUPPORTED_PAYLOAD_ALPHABET_PROFILES),
        default="safe-base32-v1",
        help="generation alphabet profile used for deterministic certification cases",
    )
    p_certify.add_argument(
        "--allow-unsafe-profile",
        action="store_true",
        help="run despite production profile violations; report is not production-certified",
    )
    p_certify.add_argument(
        "--allow-ocr-fallback",
        action="store_true",
        help="explicitly allow non-sidecar OCR fallback under reliable-airgap-v1",
    )
    p_certify.add_argument(
        "--profile-redundancy-threshold-bytes",
        type=int,
        default=1,
        help="payload-size threshold at which reliable-airgap-v1 requires redundancy or parity",
    )
    p_certify.add_argument(
        "--distortion-suite",
        choices=["none", "generated-page-basic-v1", "generated-page-stress-v1"],
        default="none",
        help="deterministic generated-page distortion suite for replayable reliability evidence",
    )
    p_certify.add_argument(
        "--distortion-required-success-rate",
        type=float,
        default=None,
        help="per-distortion success-rate gate; defaults to --require-success-rate",
    )
    p_certify.add_argument(
        "--capture-corpus-file",
        default=None,
        help=(
            "operator-supplied capture corpus manifest "
            "(schema enc2sop-transport-capture-corpus/v1)"
        ),
    )
    p_certify.add_argument(
        "--capture-corpus-only",
        action="store_true",
        help="run only the supplied capture corpus; skip generated payload/export cases",
    )
    p_certify.add_argument(
        "--capture-required-classification",
        choices=["real", "lab", "synthetic", "stress-only"],
        default=None,
        help="require at least one supplied capture case with this classification",
    )
    p_certify.add_argument(
        "--capture-required-success-rate",
        type=float,
        default=None,
        help="per-capture-classification success-rate gate; defaults to --require-success-rate",
    )
    p_certify.add_argument(
        "--require-distinct-capture-images",
        action="store_true",
        help=(
            "fail supplied capture cases whose image SHA256 values match declared "
            "reference generated pages"
        ),
    )
    p_certify.add_argument(
        "--require-real-camera-perspective-correction",
        action="store_true",
        help=(
            "fail supplied capture cases unless they provide real-camera perspective "
            "correction evidence: corpus classification real, raw_image_paths, "
            "reference_image_paths, corrected image_path outputs, and "
            "perspective_correction metadata"
        ),
    )
    p_certify.add_argument(
        "--require-physical-print-scan",
        action="store_true",
        help=(
            "fail supplied capture cases unless they provide physical print-scan "
            "evidence: capture_medium=print-scan, lab/real classification, "
            "reference_image_paths, byte-distinct scan images, and printer/scanner/dpi metadata"
        ),
    )
    p_certify.add_argument(
        "--capture-attachment-report-file",
        default=None,
        help=(
            "optional transport_capture_attachment_report.json from attach-capture-corpus; "
            "defaults to the corpus last_capture_attachment report when present"
        ),
    )
    p_certify.add_argument(
        "--require-capture-attachment-report",
        action="store_true",
        help=(
            "fail supplied capture cases unless the current capture/raw/reference image "
            "SHA256 values match the attachment report"
        ),
    )
    p_certify.add_argument(
        "--require-capture-provenance",
        action="store_true",
        help=(
            "fail supplied lab/real capture cases unless capture_metadata records "
            "session, operator, timestamp, and capture device provenance"
        ),
    )
    p_certify.add_argument(
        "--require-ocr-only-backend",
        action="store_true",
        help=(
            "require backend-specific OCR-only evidence; must use backend "
            "tesseract/easyocr/external and pages without binary sidecar"
        ),
    )
    p_certify.add_argument(
        "--ocr-only-required-success-rate",
        type=float,
        default=None,
        help="per-OCR-backend success-rate gate; defaults to --require-success-rate",
    )
    p_certify.add_argument(
        "--backend",
        choices=["sidecar", "auto", "tesseract", "easyocr", "external"],
        default="sidecar",
    )
    p_certify.add_argument("--max-compressed-kib", type=int, default=64)
    p_certify.add_argument("--chunk-chars", type=int, default=40)
    p_certify.add_argument("--lines-per-page", type=int, default=20)
    p_certify.add_argument("--font-size", type=int, default=44)
    p_certify.add_argument("--font-max-size", type=int, default=132)
    p_certify.add_argument(
        "--font-fit-mode",
        choices=["target", "fit", "fixed"],
        default="target",
    )
    p_certify.add_argument("--fixed-font-size", action="store_true")
    p_certify.add_argument(
        "--metadata-level",
        choices=["compact", "none"],
        default="compact",
    )
    p_certify.add_argument(
        "--line-separator",
        choices=list(protocol.SUPPORTED_FIELD_SEPARATORS),
        default="|",
    )
    p_certify.add_argument(
        "--line-index-mode",
        choices=["full", "chunk", "off"],
        default="full",
    )
    p_certify.add_argument(
        "--line-crc-mode",
        choices=["on", "off"],
        default="on",
    )
    p_certify.add_argument(
        "--no-sidecar",
        action="store_true",
        help="disable sidecar rendering; rejected by reliable-airgap-v1 unless unsafe override is used",
    )
    p_certify.add_argument("--redundancy-copies", type=int, default=2)
    p_certify.add_argument("--no-interleave", action="store_true")
    p_certify.add_argument("--parity-group-size", type=int, default=4)
    p_certify.add_argument("--filename-prefix", default="case")
    p_certify.add_argument("--require-success-rate", type=float, default=1.0)
    p_certify.add_argument("--lang", default="eng", help="ocr language")
    p_certify.add_argument("--psm", type=int, default=6, help="tesseract psm mode")
    p_certify.add_argument(
        "--ocr-provider-cmd",
        default=None,
        help=(
            "external OCR command template used by backend=external/auto; placeholders: "
            "{image_path} {image_name} {page_no} {lang} {psm} {manifest_path}"
        ),
    )
    p_certify.add_argument(
        "--ocr-provider-timeout-sec",
        type=int,
        default=120,
        help="timeout seconds for one external OCR command call",
    )
    p_certify.add_argument("--strict-payload-chars", action="store_true")
    p_certify.add_argument("--max-list", type=int, default=200, help="max list size in analyze")

    p_prepare_capture = sub.add_parser(
        "prepare-capture-corpus",
        help="stage printable pages and a capture corpus manifest for physical/lab certification",
    )
    p_prepare_capture.add_argument(
        "-o",
        "--output-dir",
        required=True,
        help="capture kit output directory",
    )
    p_prepare_capture.add_argument(
        "--classification",
        choices=["real", "lab", "synthetic", "stress-only"],
        default="lab",
        help="declared corpus classification for the operator-supplied captures",
    )
    p_prepare_capture.add_argument(
        "--capture-medium",
        choices=["unspecified", "camera-photo", "print-scan", "mixed"],
        default="unspecified",
        help="declared physical medium for the staged capture cases",
    )
    p_prepare_capture.add_argument(
        "--include-raw-capture-dirs",
        action="store_true",
        help=(
            "stage sibling captures/*__raw directories plus raw_image_paths and "
            "perspective_correction metadata for real camera perspective evidence"
        ),
    )
    p_prepare_capture.add_argument(
        "--perspective-correction-method",
        default=None,
        help=(
            "method text to write into staged perspective_correction metadata when "
            "--include-raw-capture-dirs is used"
        ),
    )
    p_prepare_capture.add_argument(
        "--payload-size",
        dest="payload_sizes",
        action="append",
        type=int,
        default=None,
        help="payload size in bytes; repeat to stage multiple capture cases",
    )
    p_prepare_capture.add_argument("--iterations-per-size", type=int, default=1)
    p_prepare_capture.add_argument("--seed", type=int, default=1729)
    p_prepare_capture.add_argument(
        "--profile",
        choices=["reliable-airgap-v1", "ocr-only-backend-v1"],
        default="reliable-airgap-v1",
        help=(
            "capture kit profile; reliable-airgap-v1 is the production airgap profile, "
            "ocr-only-backend-v1 is non-production backend-specific OCR evidence"
        ),
    )
    p_prepare_capture.add_argument(
        "--payload-alphabet-profile",
        choices=list(protocol.SUPPORTED_PAYLOAD_ALPHABET_PROFILES),
        default="safe-base32-v1",
        help="generation alphabet profile for staged capture-kit pages",
    )
    p_prepare_capture.add_argument(
        "--ocr-only-backend",
        choices=["tesseract", "easyocr", "external"],
        default=None,
        help=(
            "stage sidecar-free pages for backend-specific OCR-only measurement; "
            "does not certify generic OCR fallback or reliable-airgap-v1 readiness"
        ),
    )
    p_prepare_capture.add_argument(
        "--profile-redundancy-threshold-bytes",
        type=int,
        default=1,
        help="payload-size threshold at which reliable-airgap-v1 requires redundancy or parity",
    )
    p_prepare_capture.add_argument(
        "--corpus-file",
        default=None,
        help="optional corpus manifest path relative to output-dir; defaults to capture_corpus.json",
    )
    p_prepare_capture.add_argument(
        "--kit-manifest-file",
        default=None,
        help="optional kit manifest path relative to output-dir; defaults to capture_kit_manifest.json",
    )
    p_prepare_capture.add_argument(
        "--case-label-prefix",
        default="capture-case",
        help="prefix for generated capture case labels",
    )
    p_prepare_capture.add_argument(
        "--capture-metadata",
        action="append",
        default=None,
        help="default capture metadata item in KEY=VALUE form; repeat as needed",
    )
    p_prepare_capture.add_argument("--max-compressed-kib", type=int, default=64)
    p_prepare_capture.add_argument("--chunk-chars", type=int, default=40)
    p_prepare_capture.add_argument("--lines-per-page", type=int, default=20)
    p_prepare_capture.add_argument("--font-size", type=int, default=44)
    p_prepare_capture.add_argument("--font-max-size", type=int, default=132)
    p_prepare_capture.add_argument(
        "--font-fit-mode",
        choices=["target", "fit", "fixed"],
        default="target",
    )
    p_prepare_capture.add_argument("--fixed-font-size", action="store_true")
    p_prepare_capture.add_argument(
        "--metadata-level",
        choices=["compact"],
        default="compact",
        help="reliable-airgap-v1 capture kits require compact metadata",
    )
    p_prepare_capture.add_argument(
        "--line-separator",
        choices=list(protocol.SUPPORTED_FIELD_SEPARATORS),
        default="|",
    )
    p_prepare_capture.add_argument(
        "--line-index-mode",
        choices=["full", "chunk"],
        default="full",
        help="reliable-airgap-v1 capture kits require line indexing",
    )
    p_prepare_capture.add_argument(
        "--line-crc-mode",
        choices=["on"],
        default="on",
        help="reliable-airgap-v1 capture kits require line CRC",
    )
    p_prepare_capture.add_argument("--redundancy-copies", type=int, default=2)
    p_prepare_capture.add_argument("--no-interleave", action="store_true")
    p_prepare_capture.add_argument("--parity-group-size", type=int, default=4)
    p_prepare_capture.add_argument("--filename-prefix", default="capture")

    p_attach_capture = sub.add_parser(
        "attach-capture-corpus",
        help="bind operator photos/scans currently present in a prepared capture corpus",
    )
    p_attach_capture.add_argument(
        "--capture-corpus-file",
        required=True,
        help="capture corpus manifest to refresh",
    )
    p_attach_capture.add_argument(
        "-o",
        "--output-dir",
        default=None,
        help="directory for transport_capture_attachment_report.json; defaults beside corpus",
    )
    p_attach_capture.add_argument(
        "--report-file",
        default=None,
        help="optional attachment report path",
    )
    p_attach_capture.add_argument(
        "--kit-manifest-file",
        default=None,
        help="optional capture_kit_manifest.json path to refresh",
    )
    p_attach_capture.add_argument(
        "--require-captures",
        action="store_true",
        help="fail closed unless every case has at least one attached capture image",
    )
    p_attach_capture.add_argument(
        "--require-raw-captures",
        action="store_true",
        help="fail closed unless every case has at least one raw camera image attached",
    )
    p_attach_capture.add_argument(
        "--require-distinct-capture-images",
        action="store_true",
        help="fail closed when attached capture images are missing references or match generated pages",
    )
    p_attach_capture.add_argument(
        "--no-update-corpus",
        action="store_true",
        help="write only the attachment report; do not refresh capture_corpus.json",
    )
    p_attach_capture.add_argument(
        "--no-update-kit-manifest",
        action="store_true",
        help="do not refresh capture_kit_manifest.json summary fields",
    )

    p_package_capture_return = sub.add_parser(
        "package-capture-return",
        help=(
            "assemble an operator/lab return ZIP with filled return manifest and "
            "exact SHA256 capture-file inventory"
        ),
    )
    p_package_capture_return.add_argument(
        "--capture-corpus-file",
        required=True,
        help="prepared capture_corpus.json that defines expected case labels",
    )
    p_package_capture_return.add_argument(
        "--capture-root",
        required=True,
        help="folder tree containing returned captures, one subdirectory per case label",
    )
    p_package_capture_return.add_argument(
        "--raw-capture-root",
        default=None,
        help="optional folder tree containing raw camera photos by case label",
    )
    p_package_capture_return.add_argument(
        "-o",
        "--output-dir",
        required=True,
        help="directory for operator_return.zip, manifest, metadata, and report",
    )
    p_package_capture_return.add_argument(
        "--capture-metadata-manifest-file",
        default=None,
        help=(
            "optional filled enc2sop-transport-capture-metadata-manifest/v1 file "
            "to include in the return package"
        ),
    )
    p_package_capture_return.add_argument(
        "--capture-metadata",
        action="append",
        default=None,
        help="metadata KEY=VALUE to write into a generated metadata manifest; repeatable",
    )
    p_package_capture_return.add_argument(
        "--kit-manifest-file",
        default=None,
        help="optional capture_kit_manifest.json to bind in operator_return_manifest.json",
    )
    p_package_capture_return.add_argument(
        "--package-file",
        default=None,
        help="optional package ZIP path/name; defaults to operator_return.zip",
    )
    p_package_capture_return.add_argument(
        "--return-manifest-file",
        default=None,
        help="optional output path/name for operator_return_manifest.json",
    )
    p_package_capture_return.add_argument(
        "--report-file",
        default=None,
        help="optional output path/name for transport_capture_return_package_report.json",
    )
    p_package_capture_return.add_argument("--return-session-id", default=None)
    p_package_capture_return.add_argument("--operator", default=None)
    p_package_capture_return.add_argument("--returned-at-utc", default=None)
    p_package_capture_return.add_argument(
        "--allow-missing-captures",
        action="store_true",
        help="allow package assembly when some cases have no returned capture image",
    )
    p_package_capture_return.add_argument(
        "--require-raw-captures",
        action="store_true",
        help="fail closed unless every case has raw camera images",
    )
    p_package_capture_return.add_argument(
        "--require-capture-provenance",
        action="store_true",
        help=(
            "fail closed unless the packaged metadata manifest has session, operator, "
            "timestamp, and device provenance for every lab/real case"
        ),
    )
    p_package_capture_return.add_argument(
        "--allow-unmatched-labels",
        action="store_true",
        help="do not fail on extra capture-root/raw-capture-root entries",
    )

    p_ingest_capture = sub.add_parser(
        "ingest-capture-corpus",
        help="map external real/lab capture folders into a prepared capture corpus",
    )
    p_ingest_capture.add_argument(
        "--capture-corpus-file",
        required=True,
        help="prepared capture_corpus.json to update",
    )
    p_ingest_capture.add_argument(
        "--capture-root",
        required=True,
        help="directory containing one subdirectory per capture case label",
    )
    p_ingest_capture.add_argument(
        "-o",
        "--output-dir",
        default=None,
        help="directory for transport_capture_corpus_ingestion_report.json; defaults beside corpus",
    )
    p_ingest_capture.add_argument(
        "--report-file",
        default=None,
        help="optional ingestion report path",
    )
    p_ingest_capture.add_argument(
        "--kit-manifest-file",
        default=None,
        help="optional capture_kit_manifest.json path to refresh",
    )
    p_ingest_capture.add_argument(
        "--raw-capture-root",
        default=None,
        help="optional directory containing raw-photo subdirectories by case label",
    )
    p_ingest_capture.add_argument(
        "--classification",
        choices=["real", "lab", "synthetic", "stress-only"],
        default=None,
        help="override corpus classification recorded for ingestion",
    )
    p_ingest_capture.add_argument(
        "--capture-medium",
        choices=["unspecified", "camera-photo", "print-scan", "mixed"],
        default=None,
        help="capture medium to record on the corpus/cases",
    )
    p_ingest_capture.add_argument(
        "--capture-metadata",
        action="append",
        default=None,
        help="case metadata KEY=VALUE to merge into each ingested case; repeatable",
    )
    p_ingest_capture.add_argument(
        "--capture-metadata-manifest-file",
        default=None,
        help=(
            "optional enc2sop-transport-capture-metadata-manifest/v1 JSON with "
            "defaults and per-case provenance metadata"
        ),
    )
    p_ingest_capture.add_argument(
        "--require-captures",
        action="store_true",
        help="fail closed unless every case has at least one ingested capture image",
    )
    p_ingest_capture.add_argument(
        "--require-raw-captures",
        action="store_true",
        help="fail closed unless every case has at least one ingested raw camera image",
    )
    p_ingest_capture.add_argument(
        "--allow-unmatched-labels",
        action="store_true",
        help="do not fail when capture-root has extra case-label entries",
    )
    p_ingest_capture.add_argument(
        "--no-update-corpus",
        action="store_true",
        help="write only the ingestion report; do not refresh capture_corpus.json",
    )
    p_ingest_capture.add_argument(
        "--no-update-kit-manifest",
        action="store_true",
        help="do not refresh capture_kit_manifest.json summary fields",
    )

    p_correct_capture = sub.add_parser(
        "correct-capture-perspective",
        help="materialize corrected camera capture images from raw-photo directories",
    )
    p_correct_capture.add_argument(
        "--capture-corpus-file",
        required=True,
        help="capture_corpus.json containing raw_image_paths for camera cases",
    )
    p_correct_capture.add_argument(
        "-o",
        "--output-dir",
        default=None,
        help=(
            "directory for corrected images and "
            "transport_capture_perspective_correction_report.json; defaults beside corpus"
        ),
    )
    p_correct_capture.add_argument(
        "--report-file",
        default=None,
        help="optional perspective-correction report path",
    )
    p_correct_capture.add_argument(
        "--kit-manifest-file",
        default=None,
        help="optional capture_kit_manifest.json path to refresh",
    )
    p_correct_capture.add_argument(
        "--method",
        default="operator-supplied perspective correction",
        help="method label recorded in corpus perspective_correction metadata",
    )
    p_correct_capture.add_argument(
        "--mode",
        choices=_transport_certify.SUPPORTED_PERSPECTIVE_CORRECTION_MODES,
        default="copy",
        help=(
            "local deterministic correction mode; copy preserves bytes, normalize applies "
            "EXIF transpose, four-point uses per-case perspective_correction.source_corners"
        ),
    )
    p_correct_capture.add_argument(
        "--require-raw-captures",
        action="store_true",
        help="fail closed unless every case has at least one raw camera image",
    )
    p_correct_capture.add_argument(
        "--require-distinct-from-raw",
        action="store_true",
        help="fail closed unless corrected images differ byte-for-byte from raw inputs",
    )
    p_correct_capture.add_argument(
        "--no-update-corpus",
        action="store_true",
        help="write only the correction report; do not refresh capture_corpus.json",
    )
    p_correct_capture.add_argument(
        "--no-update-kit-manifest",
        action="store_true",
        help="do not refresh capture_kit_manifest.json summary fields",
    )

    p_validate_capture = sub.add_parser(
        "validate-capture-corpus",
        help="preflight operator capture corpus readiness before recovery certification",
    )
    p_validate_capture.add_argument(
        "--capture-corpus-file",
        required=True,
        help="capture_corpus.json to validate",
    )
    p_validate_capture.add_argument(
        "--output-file",
        default=None,
        help="optional path for the validation report JSON",
    )
    p_validate_capture.add_argument(
        "--profile",
        choices=["reliable-airgap-v1", "digital-sidecar-v1", "ocr-only-backend-v1"],
        default="reliable-airgap-v1",
        help="profile gates to validate against",
    )
    p_validate_capture.add_argument(
        "--backend",
        choices=["sidecar", "auto", "tesseract", "easyocr", "external"],
        default="sidecar",
        help="backend intended for the later certification run",
    )
    p_validate_capture.add_argument(
        "--allow-ocr-fallback",
        action="store_true",
        help="allow non-sidecar backend profile validation under explicit experimental fallback",
    )
    p_validate_capture.add_argument(
        "--profile-redundancy-threshold-bytes",
        type=int,
        default=1,
        help="payload-size threshold at which reliable-airgap-v1 requires redundancy or parity",
    )
    p_validate_capture.add_argument(
        "--require-captures",
        action="store_true",
        help="fail closed unless every case has at least one attached capture image",
    )
    p_validate_capture.add_argument(
        "--require-raw-captures",
        action="store_true",
        help="fail closed unless every case has at least one raw camera image attached",
    )
    p_validate_capture.add_argument(
        "--require-distinct-capture-images",
        action="store_true",
        help="fail closed when attached capture images are missing references or match generated pages",
    )
    p_validate_capture.add_argument(
        "--capture-attachment-report-file",
        default=None,
        help="optional transport_capture_attachment_report.json to validate lineage against",
    )
    p_validate_capture.add_argument(
        "--require-capture-attachment-report",
        action="store_true",
        help="fail closed unless attachment-report lineage matches the current corpus files",
    )
    p_validate_capture.add_argument(
        "--require-capture-provenance",
        action="store_true",
        help="fail closed unless lab/real cases include operator/session/device provenance metadata",
    )
    p_validate_capture.add_argument(
        "--capture-required-classification",
        choices=["real", "lab", "synthetic", "stress-only"],
        default=None,
        help="fail closed unless at least one capture case has this classification",
    )
    p_validate_capture.add_argument(
        "--require-physical-print-scan",
        action="store_true",
        help="fail closed unless physical print-scan evidence fields are present",
    )
    p_validate_capture.add_argument(
        "--require-real-camera-perspective-correction",
        action="store_true",
        help="fail closed unless real camera raw/corrected perspective evidence fields are present",
    )
    p_validate_capture.add_argument(
        "--require-ocr-only-backend",
        action="store_true",
        help="fail closed unless the corpus is sidecar-free and backend is OCR-only",
    )

    p_certify_capture_evidence = sub.add_parser(
        "certify-capture-evidence",
        help=(
            "run attach, validate, certify, archive, verify, replay, and "
            "certification-status for an operator capture corpus"
        ),
    )
    p_certify_capture_evidence.add_argument(
        "--capture-corpus-file",
        required=True,
        help="capture_corpus.json containing attached or attachable operator captures",
    )
    p_certify_capture_evidence.add_argument(
        "--capture-return-package-file",
        default=None,
        help=(
            "optional ZIP returned by an operator/lab; safely extracts captures/, "
            "optional raw_captures/, and optional metadata manifest before ingestion"
        ),
    )
    p_certify_capture_evidence.add_argument(
        "--capture-return-package-report-file",
        default=None,
        help=(
            "optional enc2sop-transport-capture-return-package/v1 report from "
            "package-capture-return; extraction fails closed unless it matches the ZIP"
        ),
    )
    p_certify_capture_evidence.add_argument(
        "--require-capture-return-manifest",
        action="store_true",
        help=(
            "fail before ingestion unless the return ZIP contains a validated "
            "enc2sop-transport-capture-return-manifest/v1"
        ),
    )
    p_certify_capture_evidence.add_argument(
        "--require-capture-return-file-inventory",
        action="store_true",
        help=(
            "fail before ingestion unless the return manifest declares and validates "
            "exact capture/raw image SHA256 and byte-size inventory"
        ),
    )
    p_certify_capture_evidence.add_argument(
        "--require-capture-return-package-report",
        action="store_true",
        help=(
            "fail before ingestion unless --capture-return-package-report-file is "
            "provided and matches the supplied return ZIP"
        ),
    )
    p_certify_capture_evidence.add_argument(
        "--capture-root",
        default=None,
        help=(
            "optional external capture folder tree to ingest before attachment; "
            "expects one subdirectory per case label"
        ),
    )
    p_certify_capture_evidence.add_argument(
        "--raw-capture-root",
        default=None,
        help="optional external raw-photo folder tree to ingest before attachment",
    )
    p_certify_capture_evidence.add_argument(
        "--capture-medium",
        choices=["unspecified", "camera-photo", "print-scan", "mixed"],
        default=None,
        help="capture medium recorded during optional ingestion",
    )
    p_certify_capture_evidence.add_argument(
        "--capture-metadata",
        action="append",
        default=None,
        help="ingestion metadata KEY=VALUE to merge into each ingested case; repeatable",
    )
    p_certify_capture_evidence.add_argument(
        "--capture-metadata-manifest-file",
        default=None,
        help=(
            "optional enc2sop-transport-capture-metadata-manifest/v1 JSON to apply "
            "during capture-root ingestion"
        ),
    )
    p_certify_capture_evidence.add_argument(
        "--allow-unmatched-labels",
        action="store_true",
        help="during optional ingestion, do not fail on extra capture-root case-label entries",
    )
    p_certify_capture_evidence.add_argument(
        "-o",
        "--output-dir",
        required=True,
        help="directory for all pipeline reports and archive artifacts",
    )
    p_certify_capture_evidence.add_argument(
        "--profile",
        choices=["reliable-airgap-v1", "digital-sidecar-v1", "ocr-only-backend-v1"],
        default="reliable-airgap-v1",
        help="profile used for validation and certification",
    )
    p_certify_capture_evidence.add_argument(
        "--backend",
        choices=["sidecar", "auto", "tesseract", "easyocr", "external"],
        default="sidecar",
        help="backend used for the certification recovery run",
    )
    p_certify_capture_evidence.add_argument("--allow-ocr-fallback", action="store_true")
    p_certify_capture_evidence.add_argument("--allow-unsafe-profile", action="store_true")
    p_certify_capture_evidence.add_argument(
        "--profile-redundancy-threshold-bytes",
        type=int,
        default=1,
    )
    p_certify_capture_evidence.add_argument("--redundancy-copies", type=int, default=2)
    p_certify_capture_evidence.add_argument("--no-interleave", action="store_true")
    p_certify_capture_evidence.add_argument("--parity-group-size", type=int, default=4)
    p_certify_capture_evidence.add_argument("--max-compressed-kib", type=int, default=64)
    p_certify_capture_evidence.add_argument("--chunk-chars", type=int, default=40)
    p_certify_capture_evidence.add_argument("--lines-per-page", type=int, default=20)
    p_certify_capture_evidence.add_argument("--font-size", type=int, default=44)
    p_certify_capture_evidence.add_argument("--font-max-size", type=int, default=132)
    p_certify_capture_evidence.add_argument(
        "--font-fit-mode",
        choices=["target", "fit", "fixed"],
        default="target",
    )
    p_certify_capture_evidence.add_argument("--fixed-font-size", action="store_true")
    p_certify_capture_evidence.add_argument(
        "--metadata-level",
        choices=["compact", "none"],
        default="compact",
    )
    p_certify_capture_evidence.add_argument(
        "--line-separator",
        choices=list(protocol.SUPPORTED_FIELD_SEPARATORS),
        default="|",
    )
    p_certify_capture_evidence.add_argument(
        "--line-index-mode",
        choices=["full", "chunk", "off"],
        default="full",
    )
    p_certify_capture_evidence.add_argument(
        "--line-crc-mode",
        choices=["on", "off"],
        default="on",
    )
    p_certify_capture_evidence.add_argument(
        "--no-sidecar",
        action="store_true",
        help=(
            "disable sidecar rendering for generated recovery context; reliable-airgap-v1 "
            "still requires sidecar evidence unless an unsafe or OCR-only profile is used"
        ),
    )
    p_certify_capture_evidence.add_argument(
        "--require-captures",
        action="store_true",
        help="fail closed unless every case has at least one attached capture image",
    )
    p_certify_capture_evidence.add_argument(
        "--allow-missing-captures",
        action="store_true",
        help="do not require every case to have an attached capture image",
    )
    p_certify_capture_evidence.add_argument(
        "--require-raw-captures",
        action="store_true",
        help="fail closed unless every case has at least one raw camera image",
    )
    p_certify_capture_evidence.add_argument(
        "--require-distinct-capture-images",
        action="store_true",
        help="fail closed when capture images match generated reference pages",
    )
    p_certify_capture_evidence.add_argument(
        "--allow-reference-identical-captures",
        action="store_true",
        help="do not require captures to be byte-distinct from generated reference pages",
    )
    p_certify_capture_evidence.add_argument(
        "--capture-attachment-report-file",
        default=None,
        help="optional attachment report output path",
    )
    p_certify_capture_evidence.add_argument(
        "--require-capture-attachment-report",
        action="store_true",
        help="require certification to match the attachment report lineage",
    )
    p_certify_capture_evidence.add_argument(
        "--allow-missing-capture-attachment-report",
        action="store_true",
        help="do not require attachment-report lineage during certification/archive/status",
    )
    p_certify_capture_evidence.add_argument(
        "--require-capture-provenance",
        action="store_true",
        help="require operator/session/timestamp/device provenance in capture_metadata",
    )
    p_certify_capture_evidence.add_argument(
        "--capture-required-classification",
        choices=["real", "lab", "synthetic", "stress-only"],
        default=None,
        help="fail closed unless the corpus includes this classification",
    )
    p_certify_capture_evidence.add_argument(
        "--capture-required-success-rate",
        type=float,
        default=None,
        help="per-capture-classification success-rate gate; defaults to --require-success-rate",
    )
    p_certify_capture_evidence.add_argument(
        "--require-success-rate",
        type=float,
        default=1.0,
        help="overall transport recovery success-rate gate",
    )
    p_certify_capture_evidence.add_argument(
        "--require-physical-print-scan",
        action="store_true",
        help="require physical print-scan evidence and claim gate",
    )
    p_certify_capture_evidence.add_argument(
        "--require-real-camera-perspective-correction",
        action="store_true",
        help="require real camera raw/corrected perspective evidence and claim gate",
    )
    p_certify_capture_evidence.add_argument(
        "--require-ocr-only-backend",
        action="store_true",
        help="require backend-specific OCR-only evidence and claim gate",
    )
    p_certify_capture_evidence.add_argument(
        "--ocr-only-required-success-rate",
        type=float,
        default=None,
        help="per-OCR-backend success-rate gate; defaults to --require-success-rate",
    )
    p_certify_capture_evidence.add_argument(
        "--require-profile-certified",
        action="store_const",
        const=True,
        default=_UNSET,
        help="require archive/verification profile_certified=true",
    )
    p_certify_capture_evidence.add_argument(
        "--no-require-profile-certified",
        dest="require_profile_certified",
        action="store_const",
        const=False,
        help="do not require profile_certified=true in archive/verification",
    )
    p_certify_capture_evidence.add_argument(
        "--require-certified-claim",
        dest="required_certified_claims",
        action="append",
        choices=_transport_certify.TRANSPORT_CERTIFICATION_CLAIMS,
        default=None,
        help="extra certification-status claim gate to require; repeatable",
    )
    p_certify_capture_evidence.add_argument("--lang", default="eng")
    p_certify_capture_evidence.add_argument("--psm", type=int, default=6)
    p_certify_capture_evidence.add_argument("--ocr-provider-cmd", default=None)
    p_certify_capture_evidence.add_argument("--ocr-provider-timeout-sec", type=int, default=120)
    p_certify_capture_evidence.add_argument("--strict-payload-chars", action="store_true")
    p_certify_capture_evidence.add_argument("--max-list", type=int, default=200)
    p_certify_capture_evidence.add_argument(
        "--kit-manifest-file",
        default=None,
        help="optional capture_kit_manifest.json path to refresh during attachment",
    )
    p_certify_capture_evidence.add_argument("--capture-return-extraction-report-file", default=None)
    p_certify_capture_evidence.add_argument("--ingestion-report-file", default=None)
    p_certify_capture_evidence.add_argument("--validation-report-file", default=None)
    p_certify_capture_evidence.add_argument("--certification-report-file", default=None)
    p_certify_capture_evidence.add_argument("--archive-file", default=None)
    p_certify_capture_evidence.add_argument("--archive-manifest-file", default=None)
    p_certify_capture_evidence.add_argument("--verification-report-file", default=None)
    p_certify_capture_evidence.add_argument(
        "--replay-output-dir",
        default=None,
        help="optional directory for extracted archive files and replay reports",
    )
    p_certify_capture_evidence.add_argument(
        "--replay-report-file",
        default=None,
        help="optional path/name for the rerun transport reliability report",
    )
    p_certify_capture_evidence.add_argument(
        "--replay-summary-file",
        default=None,
        help="optional path/name for the replay summary report JSON",
    )
    p_certify_capture_evidence.add_argument("--status-report-file", default=None)
    p_certify_capture_evidence.add_argument("--pipeline-report-file", default=None)

    p_archive_evidence = sub.add_parser(
        "archive-evidence",
        help="package a transport certification report and referenced capture artifacts for replay",
    )
    p_archive_evidence.add_argument(
        "--report-file",
        required=True,
        help="transport_reliability_report.json to archive",
    )
    p_archive_evidence.add_argument(
        "-o",
        "--output-dir",
        required=True,
        help="directory for the evidence archive ZIP and manifest",
    )
    p_archive_evidence.add_argument(
        "--capture-corpus-file",
        default=None,
        help="optional capture_corpus.json; defaults to the path recorded in the report",
    )
    p_archive_evidence.add_argument(
        "--capture-attachment-report-file",
        default=None,
        help=(
            "optional transport_capture_attachment_report.json; defaults to the path "
            "recorded in the report when present"
        ),
    )
    p_archive_evidence.add_argument(
        "--archive-file",
        default=None,
        help="optional ZIP path/name; defaults to transport_capture_evidence_archive.zip",
    )
    p_archive_evidence.add_argument(
        "--manifest-file",
        default=None,
        help=(
            "optional archive manifest path/name; defaults to "
            "transport_capture_evidence_archive_manifest.json"
        ),
    )
    p_archive_evidence.add_argument(
        "--require-successful-report",
        action="store_true",
        help="fail closed unless the input transport report has success=true",
    )
    p_archive_evidence.add_argument(
        "--require-capture-attachment-report",
        action="store_true",
        help="fail closed unless an attachment report is supplied or discoverable",
    )
    p_archive_evidence.add_argument(
        "--require-profile-certified",
        action="store_true",
        help="fail closed unless the input report has profile_certified=true",
    )
    p_archive_evidence.add_argument(
        "--require-physical-print-scan",
        action="store_true",
        help=(
            "fail closed unless the input report required and passed the physical "
            "print-scan gate"
        ),
    )
    p_archive_evidence.add_argument(
        "--require-real-camera-perspective-correction",
        action="store_true",
        help=(
            "fail closed unless the input report required and passed the real camera "
            "perspective-correction gate"
        ),
    )
    p_archive_evidence.add_argument(
        "--require-ocr-only-backend",
        action="store_true",
        help="fail closed unless the input report required and passed the OCR-only backend gate",
    )

    p_verify_evidence = sub.add_parser(
        "verify-evidence-archive",
        help="verify a transport evidence archive ZIP and gate snapshot before replay/audit use",
    )
    p_verify_evidence.add_argument(
        "--archive-file",
        required=True,
        help="transport_capture_evidence_archive.zip to verify",
    )
    p_verify_evidence.add_argument(
        "--manifest-file",
        default=None,
        help=(
            "optional external transport_capture_evidence_archive_manifest.json; "
            "defaults beside the archive when present"
        ),
    )
    p_verify_evidence.add_argument(
        "--output-file",
        default=None,
        help="optional path for the verification report JSON",
    )
    p_verify_evidence.add_argument(
        "--require-successful-report",
        action="store_true",
        help="fail closed unless the archived transport report had success=true",
    )
    p_verify_evidence.add_argument(
        "--require-profile-certified",
        action="store_true",
        help="fail closed unless the archived report had profile_certified=true",
    )
    p_verify_evidence.add_argument(
        "--require-capture-attachment-report",
        action="store_true",
        help="fail closed unless the attachment-report gate was required, passed, and archived",
    )
    p_verify_evidence.add_argument(
        "--require-physical-print-scan",
        action="store_true",
        help="fail closed unless the physical print-scan gate was required and passed",
    )
    p_verify_evidence.add_argument(
        "--require-real-camera-perspective-correction",
        action="store_true",
        help="fail closed unless the real camera perspective-correction gate was required and passed",
    )
    p_verify_evidence.add_argument(
        "--require-ocr-only-backend",
        action="store_true",
        help="fail closed unless the OCR-only backend gate was required and passed",
    )

    p_replay_evidence = sub.add_parser(
        "replay-evidence-archive",
        help="extract a transport evidence archive, rerun recovery, and compare replay outcomes",
    )
    p_replay_evidence.add_argument(
        "--archive-file",
        required=True,
        help="transport_capture_evidence_archive.zip to replay",
    )
    p_replay_evidence.add_argument(
        "-o",
        "--output-dir",
        required=True,
        help="directory for extracted archive files and replay reports",
    )
    p_replay_evidence.add_argument(
        "--manifest-file",
        default=None,
        help="optional external transport_capture_evidence_archive_manifest.json",
    )
    p_replay_evidence.add_argument(
        "--replay-report-file",
        default=None,
        help="optional path/name for the rerun transport_reliability_report.json",
    )
    p_replay_evidence.add_argument(
        "--output-file",
        default=None,
        help="optional path/name for the replay summary report JSON",
    )
    p_replay_evidence.add_argument(
        "--require-successful-report",
        action="store_true",
        help="fail closed unless the archived transport report had success=true",
    )
    p_replay_evidence.add_argument(
        "--require-profile-certified",
        action="store_true",
        help="fail closed unless the archived report had profile_certified=true",
    )
    p_replay_evidence.add_argument(
        "--require-capture-attachment-report",
        action="store_true",
        help="fail closed unless the attachment-report gate was required, passed, and archived",
    )
    p_replay_evidence.add_argument(
        "--require-physical-print-scan",
        action="store_true",
        help="fail closed unless the physical print-scan gate was required and passed",
    )
    p_replay_evidence.add_argument(
        "--require-real-camera-perspective-correction",
        action="store_true",
        help="fail closed unless the real camera perspective-correction gate was required and passed",
    )
    p_replay_evidence.add_argument(
        "--require-ocr-only-backend",
        action="store_true",
        help="fail closed unless the OCR-only backend gate was required and passed",
    )

    p_cert_status = sub.add_parser(
        "certification-status",
        help="summarize measured transport certification claims for product/launch review",
    )
    p_cert_status.add_argument(
        "--report-file",
        default=None,
        help="transport_reliability_report.json to summarize",
    )
    p_cert_status.add_argument(
        "--verification-file",
        default=None,
        help="transport_archive_verification.json to summarize",
    )
    p_cert_status.add_argument(
        "--archive-file",
        default=None,
        help=(
            "transport_capture_evidence_archive.zip to verify and summarize; requires "
            "--verify-archive"
        ),
    )
    p_cert_status.add_argument(
        "--manifest-file",
        default=None,
        help="optional archive manifest used with --archive-file",
    )
    p_cert_status.add_argument(
        "--verify-archive",
        action="store_true",
        help="verify --archive-file before deriving certification status",
    )
    p_cert_status.add_argument(
        "--require-certified-claim",
        dest="required_certified_claims",
        action="append",
        choices=_transport_certify.TRANSPORT_CERTIFICATION_CLAIMS,
        default=None,
        help=(
            "fail closed unless this measured certification claim is certified=true; "
            "valid values: {}; repeat for multiple launch claims".format(
                ", ".join(_transport_certify.TRANSPORT_CERTIFICATION_CLAIMS)
            )
        ),
    )
    p_cert_status.add_argument(
        "--output-file",
        default=None,
        help="optional path for the certification status JSON",
    )

    _mark_experimental_evidence_commands(sub)
    return parser


def _mark_experimental_evidence_commands(subparsers) -> None:
    """Label legacy evidence commands as experimental without changing behavior."""

    for command_name in EXPERIMENTAL_EVIDENCE_COMMANDS:
        command_parser = subparsers.choices.get(command_name)
        if command_parser is None:
            continue
        description = command_parser.description or ""
        if "EXPERIMENTAL evidence tooling" not in description:
            command_parser.description = (
                EXPERIMENTAL_EVIDENCE_NOTICE
                if not description
                else EXPERIMENTAL_EVIDENCE_NOTICE + "\n\n" + description
            )
        epilog = command_parser.epilog or ""
        if "not part of `soenc cm send/receive`" not in epilog:
            command_parser.epilog = (
                (epilog + "\n\n" if epilog else "")
                + "P1-S5 scope: retained as experimental evidence tooling; "
                + "not part of `soenc cm send/receive`."
            )

    for action in getattr(subparsers, "_choices_actions", []):
        if getattr(action, "dest", None) not in EXPERIMENTAL_EVIDENCE_COMMANDS:
            continue
        help_text = str(getattr(action, "help", "") or "")
        if not help_text.startswith("[experimental evidence]"):
            action.help = "[experimental evidence] " + help_text


def run_cli(argv: Optional[List[str]], transport_cls) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    transport = transport_cls(
        max_compressed_kib=getattr(args, "max_compressed_kib", 64),
        chunk_chars=getattr(args, "chunk_chars", 80),
        lines_per_page=getattr(args, "lines_per_page", 28),
        font_size=getattr(args, "font_size", 44),
        font_max_size=getattr(args, "font_max_size", 132),
        fixed_font_size=bool(getattr(args, "fixed_font_size", False)),
        font_fit_mode=getattr(args, "font_fit_mode", "target"),
        metadata_level=getattr(args, "metadata_level", "compact"),
        line_separator=getattr(args, "line_separator", "|"),
        line_index_mode=getattr(args, "line_index_mode", "full"),
        render_sidecar=(not bool(getattr(args, "no_sidecar", False))),
        line_crc_mode=getattr(args, "line_crc_mode", "on"),
        payload_alphabet_profile=getattr(
            args,
            "payload_alphabet_profile",
            "safe-base32-v1",
        ),
    )

    try:
        if args.cmd == "certify":
            result = transport.certify_reliability(
                output_dir=args.output_dir,
                payload_sizes=args.payload_sizes,
                iterations_per_size=args.iterations_per_size,
                seed=args.seed,
                backend=args.backend,
                redundancy_copies=args.redundancy_copies,
                interleave=(not args.no_interleave),
                parity_group_size=args.parity_group_size,
                filename_prefix=args.filename_prefix,
                report_file=args.report_file,
                require_success_rate=args.require_success_rate,
                lang=args.lang,
                psm=args.psm,
                ocr_provider_cmd=args.ocr_provider_cmd,
                ocr_provider_timeout_sec=args.ocr_provider_timeout_sec,
                strict_payload_chars=args.strict_payload_chars,
                max_list=args.max_list,
                profile=args.profile,
                allow_unsafe_profile=args.allow_unsafe_profile,
                allow_ocr_fallback=args.allow_ocr_fallback,
                profile_redundancy_threshold_bytes=args.profile_redundancy_threshold_bytes,
                distortion_suite=args.distortion_suite,
                distortion_required_success_rate=args.distortion_required_success_rate,
                capture_corpus_file=args.capture_corpus_file,
                include_generated_corpus=(not args.capture_corpus_only),
                require_distinct_capture_images=args.require_distinct_capture_images,
                require_real_camera_perspective_correction=(
                    args.require_real_camera_perspective_correction
                ),
                require_physical_print_scan=args.require_physical_print_scan,
                capture_attachment_report_file=args.capture_attachment_report_file,
                require_capture_attachment_report=args.require_capture_attachment_report,
                require_capture_provenance=args.require_capture_provenance,
                capture_required_classification=args.capture_required_classification,
                capture_required_success_rate=args.capture_required_success_rate,
                require_ocr_only_backend=args.require_ocr_only_backend,
                ocr_only_required_success_rate=args.ocr_only_required_success_rate,
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "prepare-capture-corpus":
            result = _transport_certify.prepare_capture_corpus_kit(
                transport=transport,
                output_dir=args.output_dir,
                classification=args.classification,
                capture_medium=args.capture_medium,
                include_raw_capture_dirs=args.include_raw_capture_dirs,
                perspective_correction_method=args.perspective_correction_method,
                payload_sizes=args.payload_sizes,
                iterations_per_size=args.iterations_per_size,
                seed=args.seed,
                redundancy_copies=args.redundancy_copies,
                interleave=(not args.no_interleave),
                parity_group_size=args.parity_group_size,
                filename_prefix=args.filename_prefix,
                corpus_file=args.corpus_file,
                kit_manifest_file=args.kit_manifest_file,
                profile=args.profile,
                profile_redundancy_threshold_bytes=args.profile_redundancy_threshold_bytes,
                capture_metadata=parse_metadata_items(args.capture_metadata),
                case_label_prefix=args.case_label_prefix,
                ocr_only_backend=args.ocr_only_backend,
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "attach-capture-corpus":
            result = transport.attach_capture_corpus(
                capture_corpus_file=args.capture_corpus_file,
                output_dir=args.output_dir,
                report_file=args.report_file,
                kit_manifest_file=args.kit_manifest_file,
                require_captures=args.require_captures,
                require_distinct_capture_images=args.require_distinct_capture_images,
                require_raw_captures=args.require_raw_captures,
                update_corpus=(not args.no_update_corpus),
                update_kit_manifest=(not args.no_update_kit_manifest),
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "package-capture-return":
            result = transport.package_capture_return(
                capture_corpus_file=args.capture_corpus_file,
                output_dir=args.output_dir,
                capture_root=args.capture_root,
                raw_capture_root=args.raw_capture_root,
                capture_metadata_manifest_file=args.capture_metadata_manifest_file,
                capture_metadata=parse_metadata_items(args.capture_metadata),
                kit_manifest_file=args.kit_manifest_file,
                package_file=args.package_file,
                return_manifest_file=args.return_manifest_file,
                report_file=args.report_file,
                return_session_id=args.return_session_id,
                operator=args.operator,
                returned_at_utc=args.returned_at_utc,
                require_captures=(not args.allow_missing_captures),
                require_raw_captures=args.require_raw_captures,
                require_capture_provenance=args.require_capture_provenance,
                require_all_case_labels=(not args.allow_unmatched_labels),
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "ingest-capture-corpus":
            result = transport.ingest_capture_corpus(
                capture_corpus_file=args.capture_corpus_file,
                capture_root=args.capture_root,
                output_dir=args.output_dir,
                report_file=args.report_file,
                kit_manifest_file=args.kit_manifest_file,
                raw_capture_root=args.raw_capture_root,
                classification=args.classification,
                capture_medium=args.capture_medium,
                capture_metadata=parse_metadata_items(args.capture_metadata),
                capture_metadata_manifest_file=args.capture_metadata_manifest_file,
                require_captures=args.require_captures,
                require_raw_captures=args.require_raw_captures,
                require_all_case_labels=(not args.allow_unmatched_labels),
                update_corpus=(not args.no_update_corpus),
                update_kit_manifest=(not args.no_update_kit_manifest),
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "correct-capture-perspective":
            result = transport.correct_capture_perspective(
                capture_corpus_file=args.capture_corpus_file,
                output_dir=args.output_dir,
                report_file=args.report_file,
                kit_manifest_file=args.kit_manifest_file,
                method=args.method,
                mode=args.mode,
                require_raw_captures=args.require_raw_captures,
                require_distinct_from_raw=args.require_distinct_from_raw,
                update_corpus=(not args.no_update_corpus),
                update_kit_manifest=(not args.no_update_kit_manifest),
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "validate-capture-corpus":
            result = transport.validate_capture_corpus(
                capture_corpus_file=args.capture_corpus_file,
                output_file=args.output_file,
                profile=args.profile,
                backend=args.backend,
                allow_ocr_fallback=args.allow_ocr_fallback,
                profile_redundancy_threshold_bytes=args.profile_redundancy_threshold_bytes,
                require_captures=args.require_captures,
                require_distinct_capture_images=args.require_distinct_capture_images,
                require_raw_captures=args.require_raw_captures,
                capture_attachment_report_file=args.capture_attachment_report_file,
                require_capture_attachment_report=args.require_capture_attachment_report,
                require_capture_provenance=args.require_capture_provenance,
                capture_required_classification=args.capture_required_classification,
                require_physical_print_scan=args.require_physical_print_scan,
                require_real_camera_perspective_correction=(
                    args.require_real_camera_perspective_correction
                ),
                require_ocr_only_backend=args.require_ocr_only_backend,
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "certify-capture-evidence":
            require_profile_certified = (
                None
                if args.require_profile_certified is _UNSET
                else bool(args.require_profile_certified)
            )
            result = transport.certify_capture_evidence_pipeline(
                capture_corpus_file=args.capture_corpus_file,
                output_dir=args.output_dir,
                capture_return_package_file=args.capture_return_package_file,
                capture_return_package_report_file=args.capture_return_package_report_file,
                require_capture_return_manifest=args.require_capture_return_manifest,
                require_capture_return_file_inventory=(
                    args.require_capture_return_file_inventory
                ),
                require_capture_return_package_report=(
                    args.require_capture_return_package_report
                ),
                capture_root=args.capture_root,
                raw_capture_root=args.raw_capture_root,
                capture_medium=args.capture_medium,
                capture_metadata=parse_metadata_items(args.capture_metadata),
                capture_metadata_manifest_file=args.capture_metadata_manifest_file,
                require_all_case_labels=(not args.allow_unmatched_labels),
                profile=args.profile,
                backend=args.backend,
                allow_ocr_fallback=args.allow_ocr_fallback,
                allow_unsafe_profile=args.allow_unsafe_profile,
                profile_redundancy_threshold_bytes=args.profile_redundancy_threshold_bytes,
                redundancy_copies=args.redundancy_copies,
                interleave=(not args.no_interleave),
                parity_group_size=args.parity_group_size,
                require_captures=(not args.allow_missing_captures),
                require_raw_captures=args.require_raw_captures,
                require_distinct_capture_images=(
                    not args.allow_reference_identical_captures
                ),
                require_capture_attachment_report=(
                    not args.allow_missing_capture_attachment_report
                ),
                require_capture_provenance=args.require_capture_provenance,
                capture_required_classification=args.capture_required_classification,
                capture_required_success_rate=args.capture_required_success_rate,
                require_success_rate=args.require_success_rate,
                require_physical_print_scan=args.require_physical_print_scan,
                require_real_camera_perspective_correction=(
                    args.require_real_camera_perspective_correction
                ),
                require_ocr_only_backend=args.require_ocr_only_backend,
                ocr_only_required_success_rate=args.ocr_only_required_success_rate,
                require_profile_certified=require_profile_certified,
                required_certified_claims=args.required_certified_claims,
                lang=args.lang,
                psm=args.psm,
                ocr_provider_cmd=args.ocr_provider_cmd,
                ocr_provider_timeout_sec=args.ocr_provider_timeout_sec,
                strict_payload_chars=args.strict_payload_chars,
                max_list=args.max_list,
                kit_manifest_file=args.kit_manifest_file,
                capture_return_extraction_report_file=(
                    args.capture_return_extraction_report_file
                ),
                ingestion_report_file=args.ingestion_report_file,
                attachment_report_file=args.capture_attachment_report_file,
                validation_report_file=args.validation_report_file,
                certification_report_file=args.certification_report_file,
                archive_file=args.archive_file,
                archive_manifest_file=args.archive_manifest_file,
                verification_report_file=args.verification_report_file,
                replay_output_dir=args.replay_output_dir,
                replay_report_file=args.replay_report_file,
                replay_summary_file=args.replay_summary_file,
                status_report_file=args.status_report_file,
                pipeline_report_file=args.pipeline_report_file,
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "archive-evidence":
            result = _transport_certify.archive_transport_evidence(
                report_file=args.report_file,
                output_dir=args.output_dir,
                capture_corpus_file=args.capture_corpus_file,
                capture_attachment_report_file=args.capture_attachment_report_file,
                archive_file=args.archive_file,
                manifest_file=args.manifest_file,
                require_successful_report=args.require_successful_report,
                require_capture_attachment_report=args.require_capture_attachment_report,
                require_physical_print_scan=args.require_physical_print_scan,
                require_real_camera_perspective_correction=(
                    args.require_real_camera_perspective_correction
                ),
                require_ocr_only_backend=args.require_ocr_only_backend,
                require_profile_certified=args.require_profile_certified,
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "verify-evidence-archive":
            result = _transport_certify.verify_transport_evidence_archive(
                archive_file=args.archive_file,
                manifest_file=args.manifest_file,
                output_file=args.output_file,
                require_successful_report=args.require_successful_report,
                require_capture_attachment_report=args.require_capture_attachment_report,
                require_physical_print_scan=args.require_physical_print_scan,
                require_real_camera_perspective_correction=(
                    args.require_real_camera_perspective_correction
                ),
                require_ocr_only_backend=args.require_ocr_only_backend,
                require_profile_certified=args.require_profile_certified,
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "replay-evidence-archive":
            result = transport.replay_transport_evidence_archive(
                archive_file=args.archive_file,
                output_dir=args.output_dir,
                manifest_file=args.manifest_file,
                replay_report_file=args.replay_report_file,
                output_file=args.output_file,
                require_successful_report=args.require_successful_report,
                require_capture_attachment_report=args.require_capture_attachment_report,
                require_physical_print_scan=args.require_physical_print_scan,
                require_real_camera_perspective_correction=(
                    args.require_real_camera_perspective_correction
                ),
                require_ocr_only_backend=args.require_ocr_only_backend,
                require_profile_certified=args.require_profile_certified,
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "certification-status":
            result = _transport_certify.summarize_transport_certification_status(
                report_file=args.report_file,
                verification_file=args.verification_file,
                archive_file=args.archive_file,
                manifest_file=args.manifest_file,
                output_file=args.output_file,
                verify_archive=args.verify_archive,
                required_certified_claims=args.required_certified_claims,
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "estimate":
            result = transport.estimate_export_artifact(
                input_file=args.input_file,
                redundancy_copies=args.redundancy_copies,
                interleave=(not args.no_interleave),
                parity_group_size=args.parity_group_size,
            )
            print_json(result)
            return 0

        if args.cmd == "export":
            result = transport.export_artifact(
                input_file=args.input_file,
                output_dir=args.output_dir,
                artifact_id=args.artifact_id,
                filename_prefix=args.filename_prefix,
                redundancy_copies=args.redundancy_copies,
                interleave=(not args.no_interleave),
                parity_group_size=args.parity_group_size,
            )
            print_json(result)
            return 0

        if args.cmd == "recover":
            result = transport.recover_artifact(
                manifest_path=args.manifest,
                ocr_input_path=args.ocr_input,
                output_file=args.output_file,
                strict_payload_chars=args.strict_payload_chars,
                corrections_file=args.corrections_file,
            )
            print_json(result)
            return 0

        if args.cmd == "verify":
            result = transport.verify_ocr_text(
                manifest_path=args.manifest,
                ocr_input_path=args.ocr_input,
                strict_payload_chars=args.strict_payload_chars,
                corrections_file=args.corrections_file,
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "replay-corrections":
            result = transport.replay_ocr_corrections(
                manifest_path=args.manifest,
                ocr_input_path=args.ocr_input,
                corrections_file=args.corrections_file,
                output_file=args.output_file,
                report_file=args.report_file,
                strict_payload_chars=args.strict_payload_chars,
                emit_corrections_file=args.emit_corrections_template,
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "verify-correction-replay":
            result = transport.verify_ocr_correction_replay_report(
                report_file=args.report_file,
                output_file=args.output_file,
                require_success=(not args.allow_failed_report),
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "certify-ocr-confusion":
            result = transport.certify_ocr_safe_confusions(
                output_dir=args.output_dir,
                report_file=args.report_file,
                payload_size=args.payload_size,
                seed=args.seed,
                redundancy_copies=args.redundancy_copies,
                parity_group_size=args.parity_group_size,
                filename_prefix=args.filename_prefix,
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "verify-ocr-confusion":
            result = transport.verify_ocr_safe_confusion_report(
                report_file=args.report_file,
                output_file=args.output_file,
                require_success=(not args.allow_failed_report),
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "archive-ocr-safe-evidence":
            result = transport.archive_ocr_safe_evidence(
                archive_file=args.archive_file,
                manifest_file=args.manifest_file,
                confusion_report_file=args.confusion_report_file,
                correction_replay_report_file=args.correction_replay_report_file,
                require_confusion_report=args.require_confusion_report,
                require_correction_replay_report=args.require_correction_replay_report,
                require_source_report_verification=args.require_source_report_verification,
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "verify-ocr-safe-evidence-archive":
            result = transport.verify_ocr_safe_evidence_archive(
                archive_file=args.archive_file,
                manifest_file=args.manifest_file,
                output_file=args.output_file,
                require_confusion_report=args.require_confusion_report,
                require_correction_replay_report=args.require_correction_replay_report,
                require_source_report_verification=args.require_source_report_verification,
                require_success=(not args.allow_failed_report),
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "analyze":
            result = transport.analyze_ocr_text(
                manifest_path=args.manifest,
                ocr_input_path=args.ocr_input,
                strict_payload_chars=args.strict_payload_chars,
                max_list=args.max_list,
                save_report_path=args.save_report,
                emit_missing_file=args.emit_missing_file,
                emit_corrections_file=args.emit_corrections_template,
                corrections_file=args.corrections_file,
            )
            print_json(result)
            return 0 if result.get("success") else 2

        if args.cmd == "ocr-extract":
            result = transport.extract_text_from_images(
                image_input_path=args.image_input,
                output_text_path=args.output_text,
                backend=args.backend,
                lang=args.lang,
                psm=args.psm,
                manifest_path=args.manifest,
                ocr_provider_cmd=args.ocr_provider_cmd,
                ocr_provider_timeout_sec=args.ocr_provider_timeout_sec,
            )
            print_json(result)
            return 0

        if args.cmd == "recover-images":
            result = transport.recover_from_images(
                manifest_path=args.manifest,
                image_input_path=args.image_input,
                output_file=args.output_file,
                backend=args.backend,
                lang=args.lang,
                psm=args.psm,
                ocr_provider_cmd=args.ocr_provider_cmd,
                ocr_provider_timeout_sec=args.ocr_provider_timeout_sec,
                strict_payload_chars=args.strict_payload_chars,
                ocr_text_output=args.ocr_text_output,
                save_analyze_report=args.save_analyze_report,
                emit_missing_file=args.emit_missing_file,
                emit_corrections_file=args.emit_corrections_template,
                corrections_file=args.corrections_file,
                max_list=args.max_list,
            )
            print_json(result)
            return 0 if result.get("success") else 2

        parser.print_help()
        return 1

    except Exception as exc:
        err = {"success": False, "error": str(exc), "cmd": args.cmd}
        print_json(err)
        return 2


__all__ = [
    "print_json",
    "save_json",
    "save_missing_chunks",
    "save_corrections_template",
    "parse_metadata_items",
    "build_parser",
    "run_cli",
]
