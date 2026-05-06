"""Transport-layer OCR dependency adapters with lazy loading."""

import importlib
import re
import shutil
from typing import List


_pytesseract = None
_easyocr = None
_numpy = None


def is_module_available(module_name: str) -> bool:
    try:
        return importlib.util.find_spec(module_name) is not None
    except Exception:
        return False


TESSERACT_PYTHON_AVAILABLE = is_module_available("pytesseract")
EASYOCR_AVAILABLE = is_module_available("easyocr")
NUMPY_AVAILABLE = is_module_available("numpy")
TESSERACT_CMD = shutil.which("tesseract")
TESSERACT_CLI_AVAILABLE = bool(TESSERACT_CMD)


def load_pytesseract_module():
    global _pytesseract
    global TESSERACT_PYTHON_AVAILABLE

    if TESSERACT_PYTHON_AVAILABLE is False:
        return None
    if _pytesseract is not None:
        TESSERACT_PYTHON_AVAILABLE = True
        return _pytesseract
    try:
        _pytesseract = importlib.import_module("pytesseract")  # type: ignore
        TESSERACT_PYTHON_AVAILABLE = True
        return _pytesseract
    except Exception:
        TESSERACT_PYTHON_AVAILABLE = False
        _pytesseract = None
        return None


def tesseract_python_available() -> bool:
    return bool(TESSERACT_PYTHON_AVAILABLE)


def load_easyocr_module():
    global _easyocr
    global EASYOCR_AVAILABLE

    if EASYOCR_AVAILABLE is False:
        return None
    if _easyocr is not None:
        EASYOCR_AVAILABLE = True
        return _easyocr
    try:
        _easyocr = importlib.import_module("easyocr")  # type: ignore
        EASYOCR_AVAILABLE = True
        return _easyocr
    except Exception:
        EASYOCR_AVAILABLE = False
        _easyocr = None
        return None


def load_numpy_module():
    global _numpy
    global NUMPY_AVAILABLE

    if NUMPY_AVAILABLE is False:
        return None
    if _numpy is not None:
        NUMPY_AVAILABLE = True
        return _numpy
    try:
        _numpy = importlib.import_module("numpy")  # type: ignore
        NUMPY_AVAILABLE = True
        return _numpy
    except Exception:
        NUMPY_AVAILABLE = False
        _numpy = None
        return None


def easyocr_available() -> bool:
    return bool(EASYOCR_AVAILABLE)


def numpy_available() -> bool:
    return bool(NUMPY_AVAILABLE)


def tesseract_runtime_mode() -> str:
    if tesseract_python_available():
        return "pytesseract"
    if TESSERACT_CLI_AVAILABLE and TESSERACT_CMD:
        return "cli"
    return ""


def build_easyocr_langs(lang: str) -> List[str]:
    """
    Map common tesseract-style language codes to EasyOCR language tags.
    Supports separators: + , ; whitespace.
    """
    source = (lang or "").strip()
    if not source:
        source = "eng"
    tokens = re.split(r"[+,;\s]+", source)
    alias = {
        "eng": "en",
        "en": "en",
        "chi_sim": "ch_sim",
        "zh_cn": "ch_sim",
        "ch_sim": "ch_sim",
        "chi_tra": "ch_tra",
        "zh_tw": "ch_tra",
        "ch_tra": "ch_tra",
        "jpn": "ja",
        "ja": "ja",
        "kor": "ko",
        "ko": "ko",
    }
    mapped = []
    for token in tokens:
        if not token:
            continue
        key = token.lower().strip().replace("-", "_")
        mapped.append(alias.get(key, key))

    if not mapped:
        mapped = ["en"]

    uniq = []
    seen = set()
    for item in mapped:
        if item in seen:
            continue
        seen.add(item)
        uniq.append(item)
    return uniq


def build_easyocr_reader(lang: str):
    easyocr_mod = load_easyocr_module()
    if easyocr_mod is None:
        raise RuntimeError("easyocr is not available in current environment")
    reader_langs = build_easyocr_langs(lang)
    return easyocr_mod.Reader(reader_langs, gpu=False), reader_langs


def refresh_flags() -> None:
    global TESSERACT_PYTHON_AVAILABLE
    global EASYOCR_AVAILABLE
    global NUMPY_AVAILABLE
    global TESSERACT_CMD
    global TESSERACT_CLI_AVAILABLE

    TESSERACT_PYTHON_AVAILABLE = is_module_available("pytesseract")
    EASYOCR_AVAILABLE = is_module_available("easyocr")
    NUMPY_AVAILABLE = is_module_available("numpy")
    TESSERACT_CMD = shutil.which("tesseract")
    TESSERACT_CLI_AVAILABLE = bool(TESSERACT_CMD)


def clear_cached_modules() -> None:
    global _pytesseract
    global _easyocr
    global _numpy

    _pytesseract = None
    _easyocr = None
    _numpy = None


__all__ = [
    "TESSERACT_PYTHON_AVAILABLE",
    "EASYOCR_AVAILABLE",
    "NUMPY_AVAILABLE",
    "TESSERACT_CMD",
    "TESSERACT_CLI_AVAILABLE",
    "is_module_available",
    "load_pytesseract_module",
    "load_easyocr_module",
    "load_numpy_module",
    "tesseract_python_available",
    "easyocr_available",
    "numpy_available",
    "tesseract_runtime_mode",
    "build_easyocr_langs",
    "build_easyocr_reader",
    "refresh_flags",
    "clear_cached_modules",
]
