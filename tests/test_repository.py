import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_plugin_manifest_is_valid_json():
    manifest = json.loads((ROOT / "plugin.json").read_text(encoding="utf-8"))
    assert manifest["pluginmetadataversion"] == 2
    assert "architecture" in manifest["type"]
    assert manifest["api"] == ["python3"]
    assert manifest["dependencies"]["pip"] == ["pypcode>=2.0.0,<4"]


def test_required_public_repository_files_exist():
    expected = {
        "README.md",
        "LICENSE",
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "plugin.json",
        "requirements.txt",
    }
    missing = sorted(name for name in expected if not (ROOT / name).is_file())
    assert not missing
