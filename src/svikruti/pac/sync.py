"""`svikruti sync`: bring privacy.yaml back in line with the code, as a reviewable diff.

Drift that has one mechanical answer is fixed in the file: a category the code
now handles is added to its activity, a new SDK becomes a processor stub, an
unmapped path becomes an activity stub. Anything needing judgement (purpose,
lawful basis, retention, contracts, policy violations) is left as a TODO or a
finding. The file is edited as text so comments and layout survive, and the
result is re-parsed and compared with the intended state before it is offered.
"""

from __future__ import annotations

import difflib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from svikruti.pac.engine import CheckResult
from svikruti.pac.generate import _group_key
from svikruti.pac.manifest import Manifest, parse_manifest
from svikruti.pac.reconcile import assign_files
from svikruti.pac.taxonomy import HIGH_RISK_CATEGORIES, slugify


class SyncError(RuntimeError):
    pass


@dataclass
class Plan:
    add_categories: Dict[str, List[str]] = field(default_factory=dict)       # activity -> categories
    remove_categories: Dict[str, List[str]] = field(default_factory=dict)
    link_processors: Dict[str, List[str]] = field(default_factory=dict)      # activity -> processor ids
    processor_categories: Dict[str, List[str]] = field(default_factory=dict) # processor -> categories
    new_processors: Dict[str, Dict[str, object]] = field(default_factory=dict)  # id -> {name, data_categories}
    remove_processors: List[str] = field(default_factory=list)
    new_activities: List[Dict[str, object]] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    def empty(self) -> bool:
        return not any([self.add_categories, self.remove_categories, self.link_processors, self.processor_categories, self.new_processors, self.remove_processors, self.new_activities])

    def summary(self) -> List[str]:
        lines = []
        for activity, categories in sorted(self.add_categories.items()):
            lines.append(f"+ {activity}: declare {', '.join(categories)}")
        for activity, processors in sorted(self.link_processors.items()):
            lines.append(f"+ {activity}: link processor {', '.join(processors)}")
        for processor, spec in sorted(self.new_processors.items()):
            lines.append(f"+ new processor {processor} (country, purpose, contract left as TODO)")
        for processor, categories in sorted(self.processor_categories.items()):
            lines.append(f"+ processor {processor}: receives {', '.join(categories)}")
        for activity in self.new_activities:
            lines.append(f"+ new activity {activity['id']} for {', '.join(activity['paths'])} (purpose, basis, retention left as TODO)")
        for activity, categories in sorted(self.remove_categories.items()):
            lines.append(f"- {activity}: remove stale {', '.join(categories)}")
        for processor in sorted(self.remove_processors):
            lines.append(f"- remove unused processor {processor}")
        return lines


def build_plan(result: CheckResult, prune: bool = False) -> Plan:
    plan = Plan()
    manifest, model = result.manifest, result.model
    declared = manifest.processor_by_key()
    flows = model.flows()
    names = model.processors()

    def want_processor(slug: str) -> str:
        processor = declared.get(slug)
        if processor:
            return processor.id
        plan.new_processors.setdefault(slug, {"name": names.get(slug, slug), "data_categories": sorted(flows.get(slug, []))})
        return slug

    for finding in result.findings:
        if finding.status != "open":
            continue
        if finding.rule == "D002":
            _append(plan.add_categories, finding.activity, finding.category)
        elif finding.rule == "D003":
            processor_id = want_processor(finding.processor)
            if finding.activity:
                _append(plan.link_processors, finding.activity, processor_id)
        elif finding.rule == "D009":
            _append(plan.processor_categories, finding.processor, finding.category)
        elif finding.rule == "D004" and prune:
            _append(plan.remove_categories, finding.activity, finding.category)
        elif finding.rule == "D005" and prune:
            plan.remove_processors.append(finding.processor)

    # Unmapped files become activity stubs, grouped the way `init` groups them.
    assignment = assign_files(model.files, manifest.activities)
    groups: Dict[str, List[str]] = {}
    for rel in sorted(rel for rel, owner in assignment.items() if owner is None):
        if model.files[rel].categories or model.files[rel].processors:
            groups.setdefault(_group_key(rel), []).append(rel)
    taken = {activity.id for activity in manifest.activities}
    for key, files in groups.items():
        categories = sorted({slug for rel in files for slug in model.files[rel].categories})
        if not categories:
            continue
        base = slugify(key.replace("/**", "").rsplit(".", 1)[0]) or "application"
        activity_id, counter = base, 2
        while activity_id in taken:
            activity_id, counter = f"{base}_{counter}", counter + 1
        taken.add(activity_id)
        processors = sorted({want_processor(slug) for rel in files for slug in model.files[rel].processors})
        plan.new_activities.append({"id": activity_id, "paths": [key], "data_categories": categories, "processors": processors})

    skipped = sorted({f.rule for f in result.open_findings() if f.rule in {"D006", "D007", "D008", "P001", "P002", "P003", "P004", "P005"}})
    if skipped:
        plan.notes.append(f"Not changed by sync (needs a person or a code fix): {', '.join(skipped)}.")
    if not prune and any(f.rule in {"D004", "D005"} and f.status == "open" for f in result.findings):
        plan.notes.append("Stale declarations (D004/D005) are kept; pass --prune to remove them.")
    return plan


def _append(mapping: Dict[str, List[str]], key: str, value: str) -> None:
    for item in value.split(","):
        if item and item not in mapping.setdefault(key, []):
            mapping[key].append(item)


# ------------------------------------------------------------------ text editing
_ITEM_RE = re.compile(r"^(\s*)-\s+(?:id|name):\s*(.+?)\s*(?:#.*)?$")


def _unquote(value: str) -> str:
    return value.strip().strip("\"'")


class _YamlEditor:
    """Line-based edits to the subset of YAML a manifest uses. Verified by re-parsing."""

    def __init__(self, text: str):
        self.lines = text.splitlines()
        self.trailing_newline = text.endswith("\n")

    def text(self) -> str:
        return "\n".join(self.lines) + ("\n" if self.trailing_newline else "")

    def _section(self, name: str) -> Optional[Tuple[int, int]]:
        """(header line, end line exclusive) of a top-level key."""
        start = next((i for i, line in enumerate(self.lines) if re.match(rf"^{re.escape(name)}\s*:", line)), None)
        if start is None:
            return None
        end = len(self.lines)
        for i in range(start + 1, len(self.lines)):
            if re.match(r"^[A-Za-z_]", self.lines[i]):
                end = i
                break
        # Trailing blank lines and top-level comments belong to whatever follows.
        while end - 1 > start and (not self.lines[end - 1].strip() or self.lines[end - 1].startswith("#")):
            end -= 1
        return start, end

    def _item(self, section: str, item_id: str) -> Tuple[int, int, str]:
        """(first line, end exclusive, key indent) of the list item whose id/name slug matches."""
        bounds = self._section(section)
        if bounds is None:
            raise SyncError(f"no `{section}:` section")
        start, end = bounds
        first, indent = None, ""
        for i in range(start + 1, end):
            match = _ITEM_RE.match(self.lines[i])
            if match and slugify(_unquote(match.group(2))) == item_id:
                first, indent = i, match.group(1)
                break
        if first is None:
            raise SyncError(f"could not find `{item_id}` under `{section}:`")
        last = end
        for i in range(first + 1, end):
            if re.match(rf"^{re.escape(indent)}-\s", self.lines[i]):
                last = i
                break
        while last - 1 > first and not self.lines[last - 1].strip():
            last -= 1
        return first, last, indent + "  "

    def edit_list(self, section: str, item_id: str, key: str, add: List[str], remove: List[str]) -> None:
        first, last, key_indent = self._item(section, item_id)
        pattern = re.compile(rf"^{re.escape(key_indent)}{re.escape(key)}\s*:\s*(.*)$")
        at = next((i for i in range(first, last) if pattern.match(self.lines[i]) or (i == first and re.match(rf"^\s*-\s+{re.escape(key)}\s*:", self.lines[i]))), None)
        if at is None:
            if add:
                self.lines.insert(first + 1, f"{key_indent}{key}: [{', '.join(add)}]")
            return
        rest = pattern.match(self.lines[at]).group(1)
        flow = re.match(r"^\[(.*?)\]\s*(#.*)?$", rest)
        if flow:
            items = [_unquote(part) for part in flow.group(1).split(",") if part.strip()]
            items = [item for item in items if slugify(item) not in remove]
            items += [item for item in add if item not in {slugify(existing) for existing in items}]
            comment = f"   {flow.group(2)}" if flow.group(2) else ""
            self.lines[at] = f"{key_indent}{key}: [{', '.join(items)}]{comment}"
            return
        if rest and not rest.startswith("#"):
            raise SyncError(f"`{key}` of `{item_id}` is not a list")
        # Block list: "- item" lines directly below.
        entry = re.compile(r"^(\s*)-\s+(.+?)\s*(?:#.*)?$")
        block = []
        for i in range(at + 1, last):
            match = entry.match(self.lines[i])
            if not match or len(match.group(1)) < len(key_indent):
                if self.lines[i].strip() and not self.lines[i].strip().startswith("#"):
                    break
                continue
            block.append((i, match.group(1), slugify(_unquote(match.group(2)))))
        for i, _, value in reversed(block):
            if value in remove:
                del self.lines[i]
        block = [(i, indent, value) for i, indent, value in block if value not in remove]
        existing = {value for _, _, value in block}
        item_indent = block[0][1] if block else key_indent + "  "
        insert_at = (block[-1][0] + 1 - 0) if block else at + 1
        for value in add:
            if value not in existing:
                self.lines.insert(insert_at, f"{item_indent}- {value}")
                insert_at += 1

    def remove_item(self, section: str, item_id: str) -> None:
        first, last, _ = self._item(section, item_id)
        del self.lines[first:last]
        while first < len(self.lines) and first > 0 and not self.lines[first].strip() and not self.lines[first - 1].strip():
            del self.lines[first]

    def append_item(self, section: str, block: List[str]) -> None:
        bounds = self._section(section)
        if bounds is None:
            if self.lines and self.lines[-1].strip():
                self.lines.append("")
            self.lines += [f"{section}:", *block]
            return
        start, end = bounds
        header = self.lines[start]
        if re.match(rf"^{re.escape(section)}\s*:\s*\[\s*\]", header):
            self.lines[start] = f"{section}:"
            self.lines[start + 1 : start + 1] = block
            return
        prefix = [""] if self.lines[end - 1].strip() and end - 1 > start else []
        self.lines[end:end] = prefix + block


def _processor_block(processor_id: str, spec: Dict[str, object]) -> List[str]:
    return [
        f"  - id: {processor_id}",
        f"    name: {json.dumps(str(spec['name']))}",
        f"    data_categories: [{', '.join(spec['data_categories'])}]   # what the code passes to this processor",
        "    purpose: TODO",
        "    country: TODO",
        "    contract: TODO",
    ]


def _activity_block(spec: Dict[str, object]) -> List[str]:
    lines = [
        f"  - id: {spec['id']}",
        f"    name: {json.dumps(str(spec['id']).replace('_', ' ').title())}",
        "    owner: TODO",
        f"    paths: [{', '.join(json.dumps(path) for path in spec['paths'])}]",
        f"    data_categories: [{', '.join(spec['data_categories'])}]",
        "    data_subjects: [TODO]",
        "    purposes: [TODO]",
        "    legal_basis: TODO",
        "    retention: TODO",
        f"    processors: [{', '.join(spec['processors'])}]",
    ]
    if set(spec["data_categories"]) & HIGH_RISK_CATEGORIES:
        lines.append("    dpia: TODO")
    return lines


def apply_plan_yaml(text: str, plan: Plan) -> str:
    editor = _YamlEditor(text)
    for processor_id, spec in sorted(plan.new_processors.items()):
        editor.append_item("processors", _processor_block(processor_id, spec))
    for spec in plan.new_activities:
        editor.append_item("processing_activities", _activity_block(spec))
    for activity in sorted(set(plan.add_categories) | set(plan.remove_categories)):
        editor.edit_list("processing_activities", activity, "data_categories", plan.add_categories.get(activity, []), plan.remove_categories.get(activity, []))
    for activity, processors in sorted(plan.link_processors.items()):
        editor.edit_list("processing_activities", activity, "processors", processors, [])
    for processor, categories in sorted(plan.processor_categories.items()):
        editor.edit_list("processors", processor, "data_categories", categories, [])
    for processor in plan.remove_processors:
        editor.remove_item("processors", processor)
        bounds = editor._section("processing_activities")
        for activity in _activity_ids(editor, bounds):
            editor.edit_list("processing_activities", activity, "processors", [], [processor])
    return editor.text()


def _activity_ids(editor: _YamlEditor, bounds: Optional[Tuple[int, int]]) -> List[str]:
    if bounds is None:
        return []
    ids = []
    for i in range(bounds[0] + 1, bounds[1]):
        match = re.match(r"^\s{0,4}-\s+id:\s*(.+?)\s*(?:#.*)?$", editor.lines[i])
        if match:
            ids.append(slugify(_unquote(match.group(1))))
    return ids


def apply_plan_json(text: str, plan: Plan) -> str:
    data = json.loads(text)
    activities = {slugify(str(item.get("id") or item.get("name"))): item for item in data.setdefault("processing_activities", [])}
    processors = {slugify(str(item.get("id") or item.get("name"))): item for item in data.setdefault("processors", [])}
    for processor_id, spec in sorted(plan.new_processors.items()):
        entry = {"id": processor_id, "name": spec["name"], "data_categories": list(spec["data_categories"]), "purpose": "TODO", "country": "TODO", "contract": "TODO"}
        data["processors"].append(entry)
        processors[processor_id] = entry
    for spec in plan.new_activities:
        data["processing_activities"].append(
            {"id": spec["id"], "name": str(spec["id"]).replace("_", " ").title(), "owner": "TODO", "paths": spec["paths"], "data_categories": spec["data_categories"],
             "data_subjects": ["TODO"], "purposes": ["TODO"], "legal_basis": "TODO", "retention": "TODO", "processors": spec["processors"]}
        )
    def edit(entry: Dict[str, object], key: str, add: List[str], remove: List[str]) -> None:
        current = [item for item in (entry.get(key) or []) if slugify(str(item)) not in remove]
        entry[key] = current + [item for item in add if item not in {slugify(str(existing)) for existing in current}]
    for activity in sorted(set(plan.add_categories) | set(plan.remove_categories)):
        edit(activities[activity], "data_categories", plan.add_categories.get(activity, []), plan.remove_categories.get(activity, []))
    for activity, linked in plan.link_processors.items():
        edit(activities[activity], "processors", linked, [])
    for processor, categories in plan.processor_categories.items():
        edit(processors[processor], "data_categories", categories, [])
    for processor in plan.remove_processors:
        data["processors"] = [item for item in data["processors"] if slugify(str(item.get("id") or item.get("name"))) != processor]
        for entry in data["processing_activities"]:
            edit(entry, "processors", [], [processor])
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n"


def _expected(manifest: Manifest, plan: Plan) -> Dict[str, object]:
    activities = {a.id: {"categories": set(a.data_categories), "processors": set(a.processors)} for a in manifest.activities}
    processors = {p.id: set(p.data_categories) for p in manifest.processors}
    for processor_id, spec in plan.new_processors.items():
        processors[processor_id] = set(spec["data_categories"])
    for spec in plan.new_activities:
        activities[spec["id"]] = {"categories": set(spec["data_categories"]), "processors": set(spec["processors"])}
    for activity, categories in plan.add_categories.items():
        activities[activity]["categories"] |= set(categories)
    for activity, categories in plan.remove_categories.items():
        activities[activity]["categories"] -= set(categories)
    for activity, linked in plan.link_processors.items():
        activities[activity]["processors"] |= set(linked)
    for processor, categories in plan.processor_categories.items():
        processors[processor] |= set(categories)
    for processor in plan.remove_processors:
        processors.pop(processor, None)
        for entry in activities.values():
            entry["processors"].discard(processor)
    return {"activities": activities, "processors": processors}


def _actual(manifest: Manifest) -> Dict[str, object]:
    return {
        "activities": {a.id: {"categories": set(a.data_categories), "processors": set(a.processors)} for a in manifest.activities},
        "processors": {p.id: set(p.data_categories) for p in manifest.processors},
    }


def sync_manifest(result: CheckResult, prune: bool = False) -> Tuple[Plan, str, str]:
    """Return (plan, original text, updated text). Raises SyncError if the edit cannot be verified."""
    path = Path(result.manifest.path or "privacy.yaml")
    original = path.read_text(encoding="utf-8")
    plan = build_plan(result, prune=prune)
    if plan.empty():
        return plan, original, original
    is_json = path.suffix.lower() == ".json"
    try:
        updated = apply_plan_json(original, plan) if is_json else apply_plan_yaml(original, plan)
        if is_json:
            reparsed = parse_manifest(json.loads(updated))
        else:
            import yaml

            reparsed = parse_manifest(yaml.safe_load(updated))
    except SyncError:
        raise
    except Exception as exc:
        raise SyncError(f"the edited manifest does not parse ({exc}); apply these changes by hand:\n  " + "\n  ".join(plan.summary())) from exc
    if _actual(reparsed) != _expected(result.manifest, plan):
        raise SyncError("could not edit this manifest's layout safely; apply these changes by hand:\n  " + "\n  ".join(plan.summary()))
    return plan, original, updated


def unified_diff(original: str, updated: str, name: str) -> str:
    return "".join(difflib.unified_diff(original.splitlines(keepends=True), updated.splitlines(keepends=True), fromfile=f"a/{name}", tofile=f"b/{name}"))
