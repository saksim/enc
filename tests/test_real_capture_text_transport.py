import importlib.util
import json
import shutil
import uuid
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def workspace_tmp_dir():
    repo_root = Path(__file__).resolve().parents[1]
    base = repo_root / ".pytest_tmp" / "real_capture_text_transport"
    path = base / uuid.uuid4().hex
    path.mkdir(parents=True, exist_ok=True)
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def load_script_module():
    repo_root = Path(__file__).resolve().parents[1]
    script_path = repo_root / "scripts" / "real_capture_text_transport.py"
    spec = importlib.util.spec_from_file_location("real_capture_text_transport", script_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class FakeTransport:
    def export_artifact(
        self,
        *,
        input_file,
        output_dir,
        artifact_id=None,
        filename_prefix="text_capture",
        redundancy_copies=2,
        interleave=True,
        parity_group_size=4,
    ):
        out_dir = Path(output_dir)
        pages_dir = out_dir / "pages"
        pages_txt_dir = out_dir / "pages_txt"
        pages_dir.mkdir(parents=True, exist_ok=True)
        pages_txt_dir.mkdir(parents=True, exist_ok=True)
        image_path = pages_dir / "{}_0001.png".format(filename_prefix)
        image_path.write_bytes(b"fake png bytes")
        text_path = pages_txt_dir / "{}_0001.txt".format(filename_prefix)
        text_path.write_text("P|0001|0001|ABC|CRC\n", encoding="ascii")
        manifest_path = out_dir / "FAKE.manifest.json"
        manifest_path.write_text(
            json.dumps(
                {
                    "artifact_id": "FAKE",
                    "raw_sha256": "0" * 64,
                    "sidecar_enabled": True,
                    "payload_alphabet_profile": "ocr-safe-human-correctable-v1",
                    "redundancy_copies": redundancy_copies,
                    "interleave_enabled": interleave,
                    "parity": {"enabled": True, "group_size": parity_group_size},
                }
            ),
            encoding="utf-8",
        )
        payload_path = out_dir / "FAKE.payload.txt"
        payload_path.write_text("ABC\n", encoding="ascii")
        return {
            "success": True,
            "artifact_id": artifact_id or "FAKE",
            "manifest_path": str(manifest_path),
            "payload_path": str(payload_path),
            "images": [str(image_path)],
            "page_texts": [str(text_path)],
            "image_count": 1,
            "page_text_count": 1,
            "total_pages": 1,
            "total_chunks": 1,
            "redundancy_copies": redundancy_copies,
            "interleave_enabled": interleave,
            "parity_enabled": True,
            "parity_group_count": 1,
            "payload_alphabet_profile": "ocr-safe-human-correctable-v1",
            "alphabet": "12356789OAEFHJKMNPRUVWXY",
            "sidecar_enabled": True,
            "line_crc_mode": "on",
            "line_index_mode": "full",
            "metadata_level": "compact",
            "output_dir": str(out_dir),
        }


def test_encrypted_text_artifact_round_trips_without_plaintext_bytes():
    module = load_script_module()

    artifact = module._build_encrypted_text_artifact(
        "sensitive launch text",
        label="case-1",
    )
    raw = json.dumps(artifact, ensure_ascii=False, sort_keys=True).encode("utf-8")

    assert b"sensitive launch text" not in raw
    decrypted = module._decrypt_text_artifact_bytes(raw)
    assert decrypted["text"] == "sensitive launch text"
    assert decrypted["plaintext_sha256"] == decrypted["expected_plaintext_sha256"]


def test_prepare_flow_stages_capture_contract_with_ocr_safe_pages():
    module = load_script_module()
    with workspace_tmp_dir() as tmp_path:
        args = module.parse_args(
            [
                "prepare",
                "--text",
                "hello capture",
                "--work-dir",
                str(tmp_path),
                "--label",
                "operator camera case",
                "--operator",
                "unit-test-operator",
                "--device",
                "unit-test-camera",
            ]
        )

        result = module.prepare_flow(args, transport_factory=lambda params: FakeTransport())

        assert result["success"] is True
        assert result["generated_page_image_count"] == 1
        corpus = json.loads((tmp_path / "capture_corpus.json").read_text(encoding="utf-8"))
        assert corpus["schema"] == module.transport_certify.CAPTURE_CORPUS_SCHEMA
        assert corpus["capture_medium"] == "camera-photo"
        case = corpus["cases"][0]
        assert case["label"] == "operator-camera-case"
        assert case["image_path"] == "captures/operator-camera-case"
        assert case["raw_image_paths"] == "raw_captures/operator-camera-case"
        assert case["capture_metadata"]["operator"] == "unit-test-operator"
        assert case["capture_metadata"]["camera"] == "unit-test-camera"

        flow = json.loads((tmp_path / "real_capture_text_flow.json").read_text(encoding="utf-8"))
        assert flow["schema"] == module.FLOW_MANIFEST_SCHEMA
        assert flow["transport_parameters"]["payload_alphabet_profile"] == (
            "ocr-safe-human-correctable-v1"
        )
        assert (tmp_path / flow["instructions_file"]).exists()


def test_real_camera_claim_requires_raw_captures_and_provenance():
    module = load_script_module()
    with workspace_tmp_dir() as tmp_path:
        args = module.parse_args(
            [
                "certify",
                "--work-dir",
                str(tmp_path),
                "--claim",
                "real-camera-perspective-correction",
            ]
        )
        flow_manifest = {
            "classification": "real",
            "capture_kind": "camera-photo",
        }

        options = module._claim_gate_options(args, flow_manifest)

        assert options["require_real_camera_perspective_correction"] is True
        assert options["require_raw_captures"] is True
        assert options["require_capture_provenance"] is True
        assert options["required_certified_claims"] == ["real-camera-perspective-correction"]
