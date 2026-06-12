"""Unified OCR provider candidate observations.

P1-A contract from the V0.3 guide:
  providers return text candidates plus optional confidence/bbox/provider/image
  metadata; they do not decide final payload validity. The transport verifier
  remains responsible for format checks, CRC/hash checks, and final decrypt.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Sequence


@dataclass(frozen=True)
class TextObservation:
    text: str
    confidence: Optional[float] = None
    bbox: Optional[List[float]] = None
    provider_name: str = ""
    image_id: str = ""

    def to_dict(self) -> Dict[str, object]:
        return {
            "text": self.text,
            "confidence": self.confidence,
            "bbox": list(self.bbox) if self.bbox is not None else None,
            "provider_name": self.provider_name,
            "image_id": self.image_id,
        }


def _coerce_confidence(value: object) -> Optional[float]:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except Exception:
        return None


def _coerce_bbox(value: object) -> Optional[List[float]]:
    if value is None:
        return None
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes, bytearray)):
        return None
    if len(value) != 4:
        return None
    out: List[float] = []
    try:
        for item in value:
            out.append(float(item))
    except Exception:
        return None
    return out


def observation_from_mapping(
    item: object,
    *,
    default_provider: str = "",
    default_image_id: str = "",
) -> Optional[TextObservation]:
    if isinstance(item, str):
        text = item
        provider_name = default_provider
        image_id = default_image_id
        confidence = None
        bbox = None
    elif isinstance(item, dict):
        raw_text = item.get("text", item.get("raw_text", item.get("candidate", "")))
        text = str(raw_text or "")
        provider_name = str(
            item.get("provider_name", item.get("provider", default_provider)) or ""
        )
        image_id = str(item.get("image_id", item.get("image", default_image_id)) or "")
        confidence = _coerce_confidence(item.get("confidence", item.get("score")))
        bbox = _coerce_bbox(item.get("bbox", item.get("box")))
    else:
        return None

    if not text.strip():
        return None
    return TextObservation(
        text=text,
        confidence=confidence,
        bbox=bbox,
        provider_name=provider_name,
        image_id=image_id,
    )


def _items_from_payload(payload: object) -> List[object]:
    if isinstance(payload, list):
        return list(payload)
    if not isinstance(payload, dict):
        return []
    for key in ("observations", "candidates", "lines"):
        value = payload.get(key)
        if isinstance(value, list):
            return list(value)
    text = payload.get("text")
    if isinstance(text, str) and text.strip():
        return [line for line in text.splitlines() if line.strip()]
    return []


def observations_from_payload(
    payload: object,
    *,
    default_provider: str = "",
    default_image_id: str = "",
) -> List[TextObservation]:
    observations: List[TextObservation] = []
    for item in _items_from_payload(payload):
        observation = observation_from_mapping(
            item,
            default_provider=default_provider,
            default_image_id=default_image_id,
        )
        if observation is not None:
            observations.append(observation)
    return observations


def observations_to_text(observations: Iterable[TextObservation]) -> str:
    return "\n".join(
        observation.text.strip()
        for observation in observations
        if observation.text.strip()
    )


__all__ = [
    "TextObservation",
    "observation_from_mapping",
    "observations_from_payload",
    "observations_to_text",
]
