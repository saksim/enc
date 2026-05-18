"""Transport manifest/page-layout helpers extracted from qrcode_helper."""

from pathlib import Path
from typing import Dict, List, Optional

from . import protocol


def get_render_layout_pages(manifest: Dict[str, object]) -> List[Dict[str, object]]:
    render_layout = manifest.get("render_layout")
    if not isinstance(render_layout, dict):
        return []
    pages = render_layout.get("pages")
    if not isinstance(pages, list):
        return []

    parsed_pages = []
    for item in pages:
        if not isinstance(item, dict):
            continue
        try:
            page_no = int(item.get("page", 0))
        except Exception:
            continue
        if page_no <= 0:
            continue
        parsed_pages.append(item)

    parsed_pages.sort(key=lambda x: int(x.get("page", 0)))
    return parsed_pages


def line_meta_has_sidecar(line_meta: Dict[str, object]) -> bool:
    if not isinstance(line_meta, dict):
        return False
    box = line_meta.get("binary_box")
    if not isinstance(box, list) or len(box) != 4:
        return False
    for key in ("binary_rows", "binary_cols", "bit_count", "payload_len"):
        try:
            if int(line_meta.get(key, 0)) <= 0:
                return False
        except Exception:
            return False
    return True


def page_layout_has_sidecar(page_layout: Dict[str, object]) -> bool:
    if not isinstance(page_layout, dict):
        return False
    raw_lines = page_layout.get("lines", [])
    if not isinstance(raw_lines, list) or not raw_lines:
        return False

    saw_data = False
    for item in raw_lines:
        if not isinstance(item, dict) or item.get("kind") != "data":
            continue
        saw_data = True
        if not line_meta_has_sidecar(item):
            return False
    return saw_data


def page_layouts_support_sidecar(page_layouts: List[Dict[str, object]]) -> bool:
    if not isinstance(page_layouts, list) or not page_layouts:
        return False
    return all(page_layout_has_sidecar(page_layout) for page_layout in page_layouts)


def manifest_has_page_entries(manifest: Dict[str, object]) -> bool:
    if not isinstance(manifest, dict):
        return False
    chunk_locations = manifest.get("chunk_locations")
    if not isinstance(chunk_locations, dict) or not chunk_locations:
        return False
    for raw_locations in chunk_locations.values():
        if not isinstance(raw_locations, list):
            continue
        for item in raw_locations:
            if not isinstance(item, dict):
                continue
            try:
                if int(item.get("page", 0)) > 0 and int(item.get("line", 0)) > 0:
                    return True
            except Exception:
                continue
    return False


def resolve_image_page_number(
    image_path: Path,
    image_index: int,
    manifest: Optional[Dict[str, object]],
) -> int:
    total_pages = 0
    if isinstance(manifest, dict):
        try:
            total_pages = int(manifest.get("total_pages", 0))
        except Exception:
            total_pages = 0

    match = protocol.PAGE_NO_FROM_NAME_PATTERN.search(image_path.stem)
    if match:
        try:
            page_no = int(match.group(1))
        except Exception:
            page_no = 0
        else:
            if page_no > 0 and (not total_pages or page_no <= total_pages):
                return page_no

    fallback = int(image_index) + 1
    if fallback > 0:
        return fallback
    return 1


def manifest_page_entries(
    manifest: Dict[str, object],
    page_no: int,
) -> List[Dict[str, int]]:
    chunk_locations = manifest.get("chunk_locations", {})
    if not isinstance(chunk_locations, dict):
        return []

    entries = []
    for chunk_key, raw_locations in chunk_locations.items():
        try:
            chunk_idx = int(chunk_key)
        except Exception:
            continue
        if not isinstance(raw_locations, list):
            continue
        for item in raw_locations:
            if not isinstance(item, dict):
                continue
            try:
                item_page = int(item.get("page"))
                line_no = int(item.get("line"))
                copy_no = int(item.get("copy", 1))
                priority = int(item.get("priority", copy_no))
            except Exception:
                continue
            if item_page != int(page_no):
                continue
            entries.append(
                {
                    "page": item_page,
                    "line": line_no,
                    "copy": copy_no,
                    "priority": priority,
                    "chunk_index": chunk_idx,
                }
            )
    entries.sort(key=lambda x: (int(x["line"]), int(x["priority"]), int(x["chunk_index"])))
    return entries


def manifest_entries_in_transport_order(manifest: Dict[str, object]) -> List[Dict[str, int]]:
    chunk_locations = manifest.get("chunk_locations", {})
    if not isinstance(chunk_locations, dict):
        return []

    entries: List[Dict[str, int]] = []
    for chunk_key, raw_locations in chunk_locations.items():
        try:
            chunk_idx = int(chunk_key)
        except Exception:
            continue
        if not isinstance(raw_locations, list):
            continue
        for item in raw_locations:
            if not isinstance(item, dict):
                continue
            try:
                item_page = int(item.get("page", 0))
                line_no = int(item.get("line", 0))
                copy_no = int(item.get("copy", 1))
                priority = int(item.get("priority", copy_no))
            except Exception:
                continue
            if item_page <= 0 or line_no <= 0:
                continue
            entries.append(
                {
                    "page": item_page,
                    "line": line_no,
                    "copy": copy_no,
                    "priority": priority,
                    "chunk_index": chunk_idx,
                }
            )
    entries.sort(key=lambda x: (int(x["page"]), int(x["line"]), int(x["copy"]), int(x["chunk_index"])))
    return entries


def manifest_chunk_payload_length(manifest: Dict[str, object], chunk_idx: int) -> int:
    chunk_lengths = manifest.get("chunk_lengths")
    if isinstance(chunk_lengths, list) and 0 <= int(chunk_idx) < len(chunk_lengths):
        try:
            return int(chunk_lengths[int(chunk_idx)])
        except Exception:
            return 0

    parity = manifest.get("parity", {})
    if not isinstance(parity, dict):
        return 0
    groups = parity.get("groups", [])
    if not isinstance(groups, list):
        return 0
    for group in groups:
        if not isinstance(group, dict):
            continue
        try:
            parity_idx = int(group.get("parity_chunk_index"))
            parity_len = int(group.get("parity_len", 0))
        except Exception:
            continue
        if parity_idx == int(chunk_idx) and parity_len > 0:
            return parity_len
    return 0


__all__ = [
    "get_render_layout_pages",
    "line_meta_has_sidecar",
    "page_layout_has_sidecar",
    "page_layouts_support_sidecar",
    "manifest_has_page_entries",
    "resolve_image_page_number",
    "manifest_page_entries",
    "manifest_entries_in_transport_order",
    "manifest_chunk_payload_length",
]
