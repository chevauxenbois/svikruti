"""Framework packs: crosswalks from framework-neutral obligations to clauses.

Every check in Svikruti is evaluated once, against a neutral obligation
(OBL-xx). A pack only says which clause of a law or standard that obligation
supports. Adding a framework is therefore a data change (one YAML file), not a
code change, and the same evidence answers DPDPA, GDPR and ISO/IEC 27701 at
once.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from svikruti.pac.taxonomy import slugify

PACK_DIR = Path(__file__).with_name("packs")
DEFAULT_FRAMEWORKS = ["dpdpa", "gdpr", "iso27701"]


class PackError(ValueError):
    pass


@dataclass
class Pack:
    id: str
    name: str
    short_name: str
    version: str = ""
    verified: str = ""
    source: str = ""
    notes: str = ""
    terms: Dict[str, str] = field(default_factory=dict)
    legal_bases: List[str] = field(default_factory=list)
    controls: Dict[str, List[Dict[str, str]]] = field(default_factory=dict)
    builtin: bool = True

    def refs(self, obligation_id: str) -> List[Dict[str, str]]:
        return self.controls.get(obligation_id, [])


def builtin_pack_ids() -> List[str]:
    return sorted(path.stem for path in PACK_DIR.glob("*.yaml"))


def load_pack(reference: str, base_dir: Optional[str] = None) -> Pack:
    """Load a built-in pack by id, or a custom pack from a YAML/JSON path."""
    builtin = PACK_DIR / f"{slugify(reference)}.yaml"
    is_path = "/" in reference or reference.endswith((".yaml", ".yml", ".json"))
    if not is_path and builtin.is_file():
        return _parse(_read(builtin), str(builtin), builtin=True)
    path = Path(reference)
    if not path.is_absolute() and base_dir:
        path = Path(base_dir) / path
    if path.is_file():
        return _parse(_read(path), str(path), builtin=False)
    raise PackError(f"unknown framework '{reference}'. Built-in: {', '.join(builtin_pack_ids())}; or pass a path to a custom pack file.")


def load_packs(references: List[str], base_dir: Optional[str] = None) -> List[Pack]:
    packs: List[Pack] = []
    seen = set()
    for reference in references or DEFAULT_FRAMEWORKS:
        pack = load_pack(reference, base_dir)
        if pack.id not in seen:
            seen.add(pack.id)
            packs.append(pack)
    return packs


def _read(path: Path) -> Any:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        return json.loads(text)
    import yaml

    return yaml.safe_load(text)


def _parse(data: Any, source: str, builtin: bool) -> Pack:
    if not isinstance(data, dict) or not data.get("id") or not isinstance(data.get("controls"), dict):
        raise PackError(f"{source}: a framework pack needs an `id` and a `controls` mapping")
    controls: Dict[str, List[Dict[str, str]]] = {}
    for obligation_id, refs in data["controls"].items():
        if not isinstance(refs, list):
            raise PackError(f"{source}: controls.{obligation_id} must be a list of {{ref, title}} entries")
        cleaned = []
        for entry in refs:
            if not isinstance(entry, dict) or not entry.get("ref"):
                raise PackError(f"{source}: controls.{obligation_id} entries need a `ref`")
            cleaned.append({key: str(value) for key, value in entry.items()})
        controls[str(obligation_id).upper()] = cleaned
    return Pack(
        id=slugify(str(data["id"])),
        name=str(data.get("name") or data["id"]),
        short_name=str(data.get("short_name") or data.get("name") or data["id"]),
        version=str(data.get("version") or ""),
        verified=str(data.get("verified") or ""),
        source=str(data.get("source") or ""),
        notes=" ".join(str(data.get("notes") or "").split()),
        terms={str(key): str(value) for key, value in (data.get("terms") or {}).items()},
        legal_bases=[slugify(str(item)) for item in (data.get("legal_bases") or [])],
        controls=controls,
        builtin=builtin,
    )
