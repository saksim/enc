"""Core transport protocol constants and helpers."""

import base64
import binascii
import hashlib
import re
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple


PROTOCOL_VERSION = "AT1"
STD_BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
SAFE_BASE32_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
OCR_SAFE_HUMAN_CORRECTABLE_PROFILE = "ocr-safe-human-correctable-v1"
OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET = "12356789OAEFHJKMNPRUVWXY"
SUPPORTED_PAYLOAD_ALPHABET_PROFILES = (
    "safe-base32-v1",
    OCR_SAFE_HUMAN_CORRECTABLE_PROFILE,
)
IMAGE_SUFFIXES = (".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".webp")
SIDECAR_BITS_PER_ROW = 50
SIDECAR_CELL_SIZE = 6
SIDECAR_CELL_GAP = 2
HASH_FRAGMENT_LEN = 32
PAYLOAD_OCR_AMBIGUITIES = {
    "2": "Z",
    "4": "H",
    "5": "S",
    "6": "G",
    "7": "T",
    "8": "B",
    "B": "8",
    "G": "6",
    "H": "4",
    "S": "5",
    "T": "7",
    "Z": "2",
}

if len(set(SAFE_BASE32_ALPHABET)) != 32:
    raise RuntimeError("SAFE_BASE32_ALPHABET must contain exactly 32 unique chars")

STD_TO_SAFE = str.maketrans(STD_BASE32_ALPHABET, SAFE_BASE32_ALPHABET)
SAFE_TO_STD = str.maketrans(SAFE_BASE32_ALPHABET, STD_BASE32_ALPHABET)
SAFE_CHAR_TO_VAL = {ch: idx for idx, ch in enumerate(SAFE_BASE32_ALPHABET)}
OCR_SAFE_VALUE_TO_CHAR = {
    idx: ch for idx, ch in enumerate(OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET)
}
OCR_SAFE_CHAR_TO_VAL = {
    ch: idx for idx, ch in enumerate(OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET)
}
OCR_SAFE_HARD_MAP = {
    "0": "O",
    "o": "O",
    "O": "O",
    "Q": "O",
    "D": "O",
    "I": "1",
    "i": "1",
    "l": "1",
    "L": "1",
    "|": "1",
    "!": "1",
    "S": "5",
    "s": "5",
    "$": "5",
    "B": "8",
    "b": "8",
    "G": "6",
    "4": "A",
}
OCR_SAFE_AMBIGUOUS_MAP = {
    "g": ("6", "9"),
    "q": ("O", "9"),
    "Z": ("2", "7"),
    "z": ("2", "7"),
}
SUPPORTED_FIELD_SEPARATORS = ("|", "$", "@")
SEPARATOR_CHAR_CLASS = r"\|$@"
SEPARATOR_FALLBACK_CHAR_CLASS = r"\|I$@T"
PAYLOAD_CHAR_CLASS = r"A-Za-z0-9\-"
PAYLOAD_FALLBACK_CHAR_CLASS = r"A-Za-z0-9$\-"

LINE_PATTERN = re.compile(
    r"^P(\d{3})L(\d{3})([" + SEPARATOR_CHAR_CLASS + r"])C(\d{5})\3([" + PAYLOAD_CHAR_CLASS + r"]+)\3([0-9A-F]{4})$"
)
LINE_PATTERN_NOCRC = re.compile(
    r"^P(\d{3})L(\d{3})([" + SEPARATOR_CHAR_CLASS + r"])C(\d{5})\3([" + PAYLOAD_CHAR_CLASS + r"]+)$"
)
LINE_PATTERN_NOSEP = re.compile(
    r"^P([0-9A-Z@]{3})(?:L|I|1)([0-9A-Z@]{3})C([0-9A-Z@]{5})([" + PAYLOAD_CHAR_CLASS + r"]+)([0-9A-FIO]{4})$"
)
LINE_PATTERN_NOSEP_NOCRC = re.compile(
    r"^P([0-9A-Z@]{3})(?:L|I|1)([0-9A-Z@]{3})C([0-9A-Z@]{5})([" + PAYLOAD_CHAR_CLASS + r"]+)$"
)
LINE_PATTERN_FALLBACK = re.compile(
    r"^P([0-9A-Z@]{3})(?:L|I|1)([0-9A-Z@]{3})([" + SEPARATOR_FALLBACK_CHAR_CLASS + r"])C([0-9A-Z@]{5})\3([" + PAYLOAD_FALLBACK_CHAR_CLASS + r"]+)\3([0-9A-FIO]{4})$"
)
LINE_PATTERN_FALLBACK_NOCRC = re.compile(
    r"^P([0-9A-Z@]{3})(?:L|I|1)([0-9A-Z@]{3})([" + SEPARATOR_FALLBACK_CHAR_CLASS + r"])C([0-9A-Z@]{5})\3([" + PAYLOAD_FALLBACK_CHAR_CLASS + r"]+)$"
)
CHUNK_PATTERN = re.compile(
    r"^C(\d{5})([" + SEPARATOR_CHAR_CLASS + r"])([" + PAYLOAD_CHAR_CLASS + r"]+)\2([0-9A-F]{4})$"
)
CHUNK_PATTERN_NOCRC = re.compile(
    r"^C(\d{5})([" + SEPARATOR_CHAR_CLASS + r"])([" + PAYLOAD_CHAR_CLASS + r"]+)$"
)
CHUNK_PATTERN_FALLBACK = re.compile(
    r"^C([0-9A-Z@]{5})([" + SEPARATOR_FALLBACK_CHAR_CLASS + r"])([" + PAYLOAD_FALLBACK_CHAR_CLASS + r"]+)\2([0-9A-FIO]{4})$"
)
CHUNK_PATTERN_FALLBACK_NOCRC = re.compile(
    r"^C([0-9A-Z@]{5})([" + SEPARATOR_FALLBACK_CHAR_CLASS + r"])([" + PAYLOAD_FALLBACK_CHAR_CLASS + r"]+)$"
)
PAYLOAD_WITH_CRC_PATTERN = re.compile(
    r"^([" + PAYLOAD_CHAR_CLASS + r"]+)([" + SEPARATOR_CHAR_CLASS + r"])([0-9A-F]{4})$"
)
PAYLOAD_WITH_CRC_FALLBACK_PATTERN = re.compile(
    r"^([" + PAYLOAD_FALLBACK_CHAR_CLASS + r"]+)([" + SEPARATOR_FALLBACK_CHAR_CLASS + r"])([0-9A-FIO]{4})$"
)
META_PATTERN = re.compile(
    r"^@META\|AT1\|ID=([A-Z0-9_-]{6,64})\|PAGE=(\d{1,3})/(\d{1,3})\|CHUNKS=(\d{1,6})\|TOTAL=(\d{1,6})$"
)
PAGECRC_PATTERN = re.compile(r"^@PAGECRC\|P(\d{3})\|([0-9A-F]{4})$")
HASH_COMPACT_PATTERN = re.compile(r"^@HS([12])\|R=([0-9A-F]{16,64})\|C=([0-9A-F]{16,64})$")
PAGE_NO_FROM_NAME_PATTERN = re.compile(r"(\d{1,4})(?!.*\d)")


def utc_now_iso() -> str:
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def crc16_hex(data: str) -> str:
    value = binascii.crc_hqx(data.encode("ascii"), 0)
    return "{:04X}".format(value)


def to_ascii_width(text: str) -> str:
    """Convert full-width chars to half-width chars."""
    converted = []
    for ch in text:
        code = ord(ch)
        if code == 12288:
            converted.append(" ")
            continue
        if 65281 <= code <= 65374:
            converted.append(chr(code - 65248))
            continue
        converted.append(ch)
    return "".join(converted)


def normalize_ocr_line(raw_line: str) -> str:
    """Normalize one OCR line into protocol-friendly text."""
    line = normalize_ocr_line_preserve_case(raw_line)
    line = line.upper()
    return line


def normalize_ocr_line_preserve_case(raw_line: str) -> str:
    """Normalize OCR separators/spacing while preserving payload glyph case."""
    line = to_ascii_width(raw_line)
    line = line.replace(chr(0x00A6), "|")
    line = line.replace(chr(0xFF5C), "|")
    line = line.replace(chr(0x01C0), "|")
    line = line.replace(chr(0x2223), "|")
    line = line.replace(chr(0xFF0C), ",")
    line = line.replace(chr(0x3002), ".")
    line = line.replace("\ufeff", "")
    line = line.replace(" ", "").replace("\t", "").replace("\r", "").replace("\n", "")
    return line


def normalize_payload(payload: str) -> str:
    """
    Conservative payload normalization for OCR confusion.
    The map only targets chars that are impossible in protocol payload.
    """
    alias = {
        "0": "Q",
        "O": "Q",
        "1": "L",
        "I": "L",
        "$": "S",
    }
    out = []
    for ch in payload:
        out.append(alias.get(ch, ch))
    return "".join(out)


def payload_alphabet_for_profile(profile: Optional[str]) -> str:
    value = str(profile or "safe-base32-v1").strip().lower()
    if value in ("", "safe-base32", "safe-base32-v1"):
        return SAFE_BASE32_ALPHABET
    if value == OCR_SAFE_HUMAN_CORRECTABLE_PROFILE:
        return OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET
    raise ValueError("unsupported payload alphabet profile: {}".format(profile))


def payload_value_map_for_profile(profile: Optional[str]) -> Dict[str, int]:
    alphabet = payload_alphabet_for_profile(profile)
    return {ch: idx for idx, ch in enumerate(alphabet)}


def payload_char_for_value(profile: Optional[str], value: int) -> str:
    alphabet = payload_alphabet_for_profile(profile)
    value = int(value)
    if value < 0 or value >= len(alphabet):
        raise ValueError("payload symbol value out of range: {}".format(value))
    return alphabet[value]


def encode_payload_for_profile(data: bytes, profile: Optional[str]) -> str:
    value = str(profile or "safe-base32-v1").strip().lower()
    if value in ("", "safe-base32", "safe-base32-v1"):
        return encode_safe_base32(data)
    if value != OCR_SAFE_HUMAN_CORRECTABLE_PROFILE:
        raise ValueError("unsupported payload alphabet profile: {}".format(profile))
    return encode_bytes_with_alphabet(data, OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET)


def decode_payload_for_profile(data: str, profile: Optional[str]) -> bytes:
    value = str(profile or "safe-base32-v1").strip().lower()
    if value in ("", "safe-base32", "safe-base32-v1"):
        return decode_safe_base32(data)
    if value != OCR_SAFE_HUMAN_CORRECTABLE_PROFILE:
        raise ValueError("unsupported payload alphabet profile: {}".format(profile))
    return decode_bytes_with_alphabet(data, OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET)


def payload_to_bits_for_profile(payload: str, profile: Optional[str]) -> str:
    value = str(profile or "safe-base32-v1").strip().lower()
    if value in ("", "safe-base32", "safe-base32-v1"):
        return safe_payload_to_bits(payload)
    if value != OCR_SAFE_HUMAN_CORRECTABLE_PROFILE:
        raise ValueError("unsupported payload alphabet profile: {}".format(profile))
    bits = []
    for ch in payload:
        bits.append("{:05b}".format(OCR_SAFE_CHAR_TO_VAL[ch]))
    return "".join(bits)


def bits_to_payload_for_profile(bits: str, expected_len: int, profile: Optional[str]) -> str:
    value = str(profile or "safe-base32-v1").strip().lower()
    if value in ("", "safe-base32", "safe-base32-v1"):
        return bits_to_safe_payload(bits, expected_len)
    if value != OCR_SAFE_HUMAN_CORRECTABLE_PROFILE:
        raise ValueError("unsupported payload alphabet profile: {}".format(profile))
    out = []
    for index in range(int(expected_len)):
        start = index * 5
        chunk = bits[start : start + 5]
        if len(chunk) != 5:
            return ""
        value_index = int(chunk, 2)
        if value_index < 0 or value_index >= len(OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET):
            return ""
        out.append(OCR_SAFE_VALUE_TO_CHAR[value_index])
    return "".join(out)


def _bounded_candidate_product(options: Iterable[Tuple[str, ...]], max_candidates: int) -> List[str]:
    candidates = [""]
    for values in options:
        next_candidates: List[str] = []
        for prefix in candidates:
            for value in values:
                next_candidates.append(prefix + value)
                if len(next_candidates) > int(max_candidates):
                    return []
        candidates = next_candidates
    return candidates


def ocr_safe_payload_candidates(raw_payload: str, max_candidates: int = 4096) -> Dict[str, object]:
    options: List[Tuple[str, ...]] = []
    normalized_chars: List[str] = []
    ambiguous_count = 0
    unexpected = []
    for raw_ch in to_ascii_width(str(raw_payload or "")):
        if raw_ch in (" ", "\t", "\r", "\n", "-"):
            continue
        if raw_ch in OCR_SAFE_AMBIGUOUS_MAP:
            choices = tuple(OCR_SAFE_AMBIGUOUS_MAP[raw_ch])
            options.append(choices)
            normalized_chars.append("{" + "".join(choices) + "}")
            ambiguous_count += 1
            continue
        hard = OCR_SAFE_HARD_MAP.get(raw_ch)
        if hard is not None:
            options.append((hard,))
            normalized_chars.append(hard)
            continue
        if raw_ch in OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET:
            options.append((raw_ch,))
            normalized_chars.append(raw_ch)
            continue
        unexpected.append(raw_ch)

    candidates = _bounded_candidate_product(options, max_candidates=max_candidates)
    return {
        "normalized_text": "".join(normalized_chars),
        "candidates": candidates,
        "candidate_count": len(candidates),
        "ambiguous_count": ambiguous_count,
        "unexpected_chars": "".join(sorted(set(unexpected))),
        "candidate_limit_exceeded": bool(options and not candidates),
    }


def encode_bytes_with_alphabet(data: bytes, alphabet: str) -> str:
    if len(set(alphabet)) != len(alphabet) or len(alphabet) < 2:
        raise ValueError("payload alphabet must contain at least two unique chars")
    if not data:
        return ""
    base = len(alphabet)
    leading_zero_count = 0
    for byte in data:
        if byte != 0:
            break
        leading_zero_count += 1
    number = int.from_bytes(data, "big")
    digits: List[str] = []
    while number:
        number, remainder = divmod(number, base)
        digits.append(alphabet[remainder])
    encoded_number = "".join(reversed(digits))
    return (alphabet[0] * leading_zero_count) + encoded_number


def decode_bytes_with_alphabet(text: str, alphabet: str) -> bytes:
    if len(set(alphabet)) != len(alphabet) or len(alphabet) < 2:
        raise ValueError("payload alphabet must contain at least two unique chars")
    value_map = {ch: idx for idx, ch in enumerate(alphabet)}
    payload = str(text or "")
    leading_zero_count = 0
    for ch in payload:
        if ch != alphabet[0]:
            break
        leading_zero_count += 1
    number = 0
    for ch in payload[leading_zero_count:]:
        if ch not in value_map:
            raise ValueError("payload contains a character outside selected alphabet")
        number = (number * len(alphabet)) + value_map[ch]
    body = b""
    if number:
        body = number.to_bytes((number.bit_length() + 7) // 8, "big")
    return (b"\x00" * leading_zero_count) + body


def normalize_protocol_signature(line: str) -> str:
    """
    Normalize key protocol markers that OCR commonly confuses.
    Example: P0011001|...  -> P001L001|...
    """
    if not line:
        return line
    if line.startswith("@METAIAT"):
        line = line.replace("@METAI", "@META|", 1).replace("I|ID=", "|ID=", 1)
        line = line.replace("IPAGE=", "|PAGE=").replace("ICHUNKS=", "|CHUNKS=").replace(
            "ITOTAL=", "|TOTAL="
        )
        line = line.replace("ATLI", "AT1|")
    if line.startswith("@PAGECRCIP"):
        line = line.replace("@PAGECRCIP", "@PAGECRC|P", 1)
    if line.startswith("@CFGIAT"):
        line = line.replace("@CFGI", "@CFG|", 1).replace("ATLI", "AT1|", 1)
        line = (
            line.replace("ICC=", "|CC=")
            .replace("ILP=", "|LP=")
            .replace("IRC=", "|RC=")
            .replace("IIL=", "|IL=")
            .replace("IPG=", "|PG=")
            .replace("ICS=", "|CS=")
            .replace("IRS=", "|RS=")
        )
    line = line.replace("|ATLI|", "|AT1|")
    if line.startswith("@CHI|"):
        line = line.replace("@CHI|", "@CH1|", 1)
    if line.startswith("@CHL|"):
        line = line.replace("@CHL|", "@CH1|", 1)
    if line.startswith("@RHI|"):
        line = line.replace("@RHI|", "@RH1|", 1)
    if line.startswith("@RHL|"):
        line = line.replace("@RHL|", "@RH1|", 1)
    if line.startswith("@CHZ|"):
        line = line.replace("@CHZ|", "@CH2|", 1)
    if line.startswith("@RHZ|"):
        line = line.replace("@RHZ|", "@RH2|", 1)
    if line.startswith("@HSI|"):
        line = line.replace("@HSI|", "@HS1|", 1)
    if line.startswith("@HSL|"):
        line = line.replace("@HSL|", "@HS1|", 1)
    if line.startswith("@HSZ|"):
        line = line.replace("@HSZ|", "@HS2|", 1)

    if line.startswith("P") and len(line) > 8:
        chars = list(line)
        if chars[4] in ("1", "I"):
            chars[4] = "L"
        line = "".join(chars)

    if len(line) >= 7 and line[0] in ("G", "Q", "O", "D", "@"):
        sep = line[6]
        if sep in ("|", "$", "@", "I", "T"):
            token = normalize_digit_token(line[1:6])
            if len(token) == 5 and token.isdigit():
                normalized_sep = "|" if sep in ("I", "T") else sep
                line = "C{}{}{}".format(token, normalized_sep, line[7:])
    return line


def normalize_digit_token(token: str) -> str:
    alias = {
        "O": "0",
        "Q": "0",
        "D": "0",
        "@": "0",
        "C": "0",
        "I": "1",
        "L": "1",
        "Z": "2",
        "M": "4",
        "H": "4",
        "S": "5",
        "G": "6",
        "T": "7",
        "B": "8",
    }
    return "".join(alias.get(ch, ch) for ch in token)


def normalize_page_line_token(token: str) -> str:
    """
    OCR normalization for page/line serials (Pxxx/Lxxx).
    Page/line fields are short and bounded, so we collapse more glyph ambiguities.
    """
    alias = {
        "O": "0",
        "Q": "0",
        "D": "0",
        "@": "0",
        "G": "0",
        "C": "0",
        "I": "1",
        "L": "1",
        "Z": "2",
        "M": "4",
        "H": "4",
        "S": "5",
        "T": "7",
        "B": "8",
    }
    return "".join(alias.get(ch, ch) for ch in token)


def normalize_hex_token(token: str) -> str:
    cleaned = []
    for ch in to_ascii_width(token).upper():
        if ch in (" ", "\t", "\r", "\n"):
            continue
        if ch not in "0123456789ABCDEFOILS":
            continue
        cleaned.append(ch)
    return "".join(cleaned).replace("O", "0").replace("I", "1").replace("L", "1").replace("S", "5")


def parse_cfg_line(line: str) -> Optional[Dict[str, int]]:
    if not line.startswith("@CFG|AT1|"):
        return None
    parts = line.split("|")
    values: Dict[str, int] = {}
    for item in parts[2:]:
        if "=" not in item:
            return None
        key, value = item.split("=", 1)
        try:
            values[key] = int(normalize_digit_token(value))
        except Exception:
            return None
    required = {"CC", "LP", "RC", "IL", "PG", "CS", "RS"}
    if not required.issubset(set(values.keys())):
        return None
    return values


def parse_hash_fragment_line(line: str) -> Optional[Tuple[str, int, str]]:
    if not line.startswith("@") or "|" not in line:
        return None
    tag, payload = line.split("|", 1)
    if len(tag) != 4:
        return None
    kind = tag[1:3]
    if kind not in ("RH", "CH"):
        return None
    try:
        part_no = int(normalize_digit_token(tag[3]))
    except Exception:
        return None
    if part_no not in (1, 2):
        return None
    normalized = normalize_hex_token(payload)
    if len(normalized) < HASH_FRAGMENT_LEN:
        return None
    return kind, part_no, normalized[:HASH_FRAGMENT_LEN]


def parse_hash_compact_line(line: str) -> Optional[Tuple[int, str, str]]:
    match = HASH_COMPACT_PATTERN.match(line)
    if not match:
        return None
    try:
        part_no = int(normalize_digit_token(match.group(1)))
    except Exception:
        return None
    if part_no not in (1, 2):
        return None
    raw_rh = normalize_hex_token(match.group(2))
    raw_ch = normalize_hex_token(match.group(3))
    if len(raw_rh) < HASH_FRAGMENT_LEN or len(raw_ch) < HASH_FRAGMENT_LEN:
        return None
    return part_no, raw_rh[:HASH_FRAGMENT_LEN], raw_ch[:HASH_FRAGMENT_LEN]


def levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    prev = list(range(len(right) + 1))
    for left_index, left_ch in enumerate(left, 1):
        current = [left_index]
        for right_index, right_ch in enumerate(right, 1):
            substitution = prev[right_index - 1] + (0 if left_ch == right_ch else 1)
            insertion = current[right_index - 1] + 1
            deletion = prev[right_index] + 1
            current.append(min(substitution, insertion, deletion))
        prev = current
    return prev[-1]


def encode_safe_base32(data: bytes) -> str:
    standard = base64.b32encode(data).decode("ascii").rstrip("=")
    return standard.translate(STD_TO_SAFE)


def decode_safe_base32(data: str) -> bytes:
    standard = data.translate(SAFE_TO_STD)
    padding = (-len(standard)) % 8
    if padding:
        standard = standard + ("=" * padding)
    return base64.b32decode(standard.encode("ascii"))


def safe_base32_encoded_length(byte_len: int) -> int:
    if byte_len <= 0:
        return 0
    full_groups, remainder = divmod(int(byte_len), 5)
    length = full_groups * 8
    extra = {0: 0, 1: 2, 2: 4, 3: 5, 4: 7}[remainder]
    return length + extra


def safe_payload_to_bits(payload: str) -> str:
    bits = []
    for ch in payload:
        bits.append("{:05b}".format(SAFE_CHAR_TO_VAL[ch]))
    return "".join(bits)


def bits_to_safe_payload(bits: str, expected_len: int) -> str:
    out = []
    for index in range(int(expected_len)):
        start = index * 5
        chunk = bits[start : start + 5]
        if len(chunk) != 5:
            return ""
        value = int(chunk, 2)
        if value < 0 or value >= len(SAFE_BASE32_ALPHABET):
            return ""
        out.append(SAFE_BASE32_ALPHABET[value])
    return "".join(out)


__all__ = [
    "PROTOCOL_VERSION",
    "STD_BASE32_ALPHABET",
    "SAFE_BASE32_ALPHABET",
    "OCR_SAFE_HUMAN_CORRECTABLE_PROFILE",
    "OCR_SAFE_HUMAN_CORRECTABLE_ALPHABET",
    "SUPPORTED_PAYLOAD_ALPHABET_PROFILES",
    "IMAGE_SUFFIXES",
    "SIDECAR_BITS_PER_ROW",
    "SIDECAR_CELL_SIZE",
    "SIDECAR_CELL_GAP",
    "HASH_FRAGMENT_LEN",
    "PAYLOAD_OCR_AMBIGUITIES",
    "SAFE_CHAR_TO_VAL",
    "OCR_SAFE_CHAR_TO_VAL",
    "OCR_SAFE_HARD_MAP",
    "OCR_SAFE_AMBIGUOUS_MAP",
    "SUPPORTED_FIELD_SEPARATORS",
    "LINE_PATTERN",
    "LINE_PATTERN_NOCRC",
    "LINE_PATTERN_NOSEP",
    "LINE_PATTERN_NOSEP_NOCRC",
    "LINE_PATTERN_FALLBACK",
    "LINE_PATTERN_FALLBACK_NOCRC",
    "CHUNK_PATTERN",
    "CHUNK_PATTERN_NOCRC",
    "CHUNK_PATTERN_FALLBACK",
    "CHUNK_PATTERN_FALLBACK_NOCRC",
    "PAYLOAD_WITH_CRC_PATTERN",
    "PAYLOAD_WITH_CRC_FALLBACK_PATTERN",
    "META_PATTERN",
    "PAGECRC_PATTERN",
    "HASH_COMPACT_PATTERN",
    "PAGE_NO_FROM_NAME_PATTERN",
    "utc_now_iso",
    "sha256_hex",
    "crc16_hex",
    "to_ascii_width",
    "normalize_ocr_line",
    "normalize_ocr_line_preserve_case",
    "normalize_payload",
    "payload_alphabet_for_profile",
    "payload_value_map_for_profile",
    "payload_char_for_value",
    "encode_payload_for_profile",
    "decode_payload_for_profile",
    "payload_to_bits_for_profile",
    "bits_to_payload_for_profile",
    "ocr_safe_payload_candidates",
    "encode_bytes_with_alphabet",
    "decode_bytes_with_alphabet",
    "normalize_protocol_signature",
    "normalize_digit_token",
    "normalize_page_line_token",
    "normalize_hex_token",
    "parse_cfg_line",
    "parse_hash_fragment_line",
    "parse_hash_compact_line",
    "levenshtein_distance",
    "encode_safe_base32",
    "decode_safe_base32",
    "safe_base32_encoded_length",
    "safe_payload_to_bits",
    "bits_to_safe_payload",
]
