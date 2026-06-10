import json

from enc2sop.transport import ocr_observations
from enc2sop.transport import ocr_runtime


def test_text_observation_payload_preserves_candidate_metadata() -> None:
    payload = {
        "observations": [
            {
                "text": "P001L001|C00000|ABCDEFGH|FF8F",
                "confidence": "0.91",
                "bbox": [1, 2, 30, 40],
                "provider_name": "model-a",
                "image_id": "shot-001",
            }
        ]
    }

    observations = ocr_observations.observations_from_payload(payload)

    assert len(observations) == 1
    assert observations[0].text.startswith("P001L001")
    assert observations[0].confidence == 0.91
    assert observations[0].bbox == [1.0, 2.0, 30.0, 40.0]
    assert observations[0].provider_name == "model-a"
    assert observations[0].image_id == "shot-001"


def test_external_ocr_json_observations_flatten_to_verifier_text() -> None:
    raw = json.dumps(
        {
            "observations": [
                {"text": "P001L001|C00000|ABCDEFGH|FF8F", "confidence": 0.99},
                {"text": "P001L002|C00001|IJKL2345|CC10", "confidence": 0.88},
            ]
        }
    )

    text = ocr_runtime.parse_external_ocr_stdout(raw)

    assert text.splitlines() == [
        "P001L001|C00000|ABCDEFGH|FF8F",
        "P001L002|C00001|IJKL2345|CC10",
    ]


def test_external_ocr_json_text_compatibility_is_retained() -> None:
    raw = json.dumps({"text": "P001L001|C00000|ABCDEFGH|FF8F\n"})

    assert ocr_runtime.parse_external_ocr_stdout(raw).strip() == "P001L001|C00000|ABCDEFGH|FF8F"
