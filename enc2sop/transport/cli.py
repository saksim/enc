"""Transport CLI/parser and output helpers extracted from qrcode_helper."""

import argparse
import json
from pathlib import Path
from typing import Dict, List, Optional

from . import protocol


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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Airgap transport layer for encrypted small artifacts."
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

    p_verify = sub.add_parser("verify", help="verify OCR text against manifest")
    p_verify.add_argument(
        "-m",
        "--manifest",
        default=None,
        help="manifest json path; optional when OCR text contains embedded export metadata",
    )
    p_verify.add_argument("-t", "--ocr-input", required=True, help="ocr text file/dir")
    p_verify.add_argument("--strict-payload-chars", action="store_true")

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
    p_recover_images.add_argument("--max-list", type=int, default=200, help="max list size in analyze")

    return parser


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
    )

    try:
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
            )
            print_json(result)
            return 0

        if args.cmd == "verify":
            result = transport.verify_ocr_text(
                manifest_path=args.manifest,
                ocr_input_path=args.ocr_input,
                strict_payload_chars=args.strict_payload_chars,
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
    "build_parser",
    "run_cli",
]
