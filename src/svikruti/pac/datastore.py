"""What happens to stored personal data: is it protected, and can it be erased?

Two questions privacy teams ask about every table and model, answered from code:

* **Protection.** Is a high-risk field (Aadhaar, PAN, health) stored encrypted,
  tokenised, hashed or masked? UIDAI's Aadhaar Data Vault circulars, DPDP Rule 6
  and GDPR Art. 32 all expect it. Evidence is the column's own declaration
  (``EncryptedCharField``, ``@Convert``, ``aadhaar_hash``) or a write that wraps the
  value (``aadhaar=encrypt_field(payload["aadhaar"])``).
* **Erasure.** Does any code path delete or anonymise this store? An erasure
  request that never reaches a table leaves residual data. Erasure paths are
  functions named for it (``delete_user``, ``anonymize_customer``,
  ``handle_erasure_request``, ``purge_expired_records``), plus any listed under
  ``erasure.handlers`` in privacy.yaml, plus the functions they call. A store is
  covered when one of those paths names it, or when it cascades from a store that
  is covered (``ForeignKey(..., on_delete=CASCADE)``, ``REFERENCES x ON DELETE CASCADE``).

Both are evidence that something is *present in code*, not proof that it runs in
production. They are reported with the line that justifies them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

_PROTECTED_DECLARATION_RE = re.compile(
    r"encrypt|cipher|fernet|pgp_sym|\baes(?:_?gcm|_?256)?\b|@convert|tokeni[sz]|vault|_token\b|_hash(?:ed)?\b|hashed_|_digest\b|hmac|"
    r"_masked\b|masked_|_last_?4\b|last_?4_|_ref(?:erence)?(?:_key)?\b|reference_key",
    re.IGNORECASE,
)
_BINARY_COLUMN_RE = re.compile(r"\b(?:LargeBinary|BinaryField|BYTEA|bytea|VARBINARY|BLOB|Bytes)\b|\[\]byte|\bbytes\b")
_PROTECTING_CALL_RE = re.compile(
    r"(?<![\w$])((?:[A-Za-z_$][\w$.]*?)?(?:encrypt|tokeni[sz]e|vault|hash|hmac|digest|mask|redact|pseudonymi[sz]e|seal|protect)\w*)\s*\(",
    re.IGNORECASE,
)
_PROTECTION_KINDS = (
    ("tokenised", re.compile(r"tokeni[sz]|vault|_ref(?:erence)?(?:_key)?\b|reference_key", re.IGNORECASE)),
    ("encrypted", re.compile(r"encrypt|cipher|fernet|pgp_sym|\baes(?:_?gcm|_?256)?\b|@convert|seal|protect", re.IGNORECASE)),
    ("hashed", re.compile(r"hash|hmac|digest", re.IGNORECASE)),
    ("masked", re.compile(r"mask|last_?4|redact|pseudonymi", re.IGNORECASE)),
)
PROTECTED_KINDS = {"encrypted", "tokenised", "hashed", "masked"}

_ERASURE_NAME_RE = re.compile(
    r"^_*(?:handle_|process_|run_|do_|perform_|execute_|async_)?(?:"
    r"(?:delete|erase|purge|anonymi[sz]e|pseudonymi[sz]e|forget|wipe|scrub|destroy|remove|hard_delete)_?"
    r"(?:user|account|customer|applicant|member|profile|person|personal_data|subject|data|me|patient|student|borrower|client|contact|lead|employee)s?(?:_|$)"
    r"|(?:purge|delete|cleanup|clean_up|expire|prune)_?(?:old|expired|stale|inactive)\w*"
    r"|(?:apply|enforce)_?retention\w*"
    r")"
    r"|(?:^|_)(?:gdpr|dsar|dsr|right_?to_?(?:erasure|be_?forgotten|delete)|forget_?me)(?:_|$)"
    r"|(?:^|_)(?:user|account|customer|applicant|member|profile|patient|personal_data)_?(?:delete|deletion|erasure|anonymi[sz]ation|purge)(?:_|$)"
    r"|(?:^|_)(?:erasure|deletion)_?request(?:_|$)",
)
_PERSISTENT_HEADER_RE = re.compile(
    r"models\.Model|db\.Model|\bModel\)|\(Base\)|DeclarativeBase|SQLModel|\bDocument\)|@Entity|@Table|@Document|"
    r"create\s+table|^\s*model\s+\w+\s*\{|\.define\(|\bSchema\(|(?:pg|mysql|sqlite)Table\(|create_table|ActiveRecord|ApplicationRecord|"
    r"gorm\.Model|Eloquent|extends\s+Model\b|@Column",
    re.IGNORECASE,
)
_PERSISTENT_PATH_RE = re.compile(r"(?:^|/)(?:models?|entities|entity|schema|db|migrations?|prisma)(?:/|\.|$)|models\.py$|schema\.(?:sql|prisma|rb)$", re.IGNORECASE)
_TRANSIENT_HEADER_RE = re.compile(
    r"\((?:[\w.]*\.)?(?:BaseModel|TypedDict|NamedTuple|Enum|IntEnum|StrEnum|Serializer|ModelSerializer|Form|ModelForm|Schema|InputObjectType|ObjectType|Struct)\)"
    r"|@dataclass|\binterface\s+\w+|\bclass\s+\w+(?:Request|Response|Payload|Dto|DTO|Input|Output|Form|Serializer|Schema|Props|Args|Params)\b",
)
_TRANSIENT_PATH_RE = re.compile(r"(?:^|/)(?:graphql|serializers?|schemas?/response|response_schemas|dto|dtos|forms?|views?|api/types|types)(?:/|\.py|\.ts|$)", re.IGNORECASE)
_CONTAINER_RES = (
    re.compile(r"^\s*create\s+table\s+(?:if\s+not\s+exists\s+)?[`\"\[]?([\w.]+)", re.IGNORECASE),   # SQL
    re.compile(r"^\s*(?:model|type|enum)\s+(\w+)\s*\{"),                                              # Prisma / GraphQL
    re.compile(r"^\s*(?:export\s+)?(?:abstract\s+)?(?:public\s+|final\s+|data\s+)*class\s+(\w+)"),   # Python / Java / Kotlin / TS / PHP / Ruby
    re.compile(r"^\s*type\s+(\w+)\s+struct\b"),                                                       # Go
    re.compile(r"^\s*(?:export\s+)?interface\s+(\w+)"),                                               # TS
    re.compile(r"\b(?:define|model)\(\s*[\"'](\w+)[\"']"),                                            # Sequelize / Mongoose
    re.compile(r"\bcreate_table\s+[:\"'](\w+)"),                                                      # Rails migration
)

_CASCADE_RES = (
    # Django: ForeignKey(Customer, on_delete=models.CASCADE) / OneToOneField(User, models.CASCADE)
    re.compile(r"(?:ForeignKey|OneToOneField|ParentalKey)\(\s*[\"']?(?:[\w.]+\.)?(\w+)[\"']?\s*,[^)\n]*?(?:on_delete\s*=\s*)?(?:models\.)?CASCADE\b"),
    re.compile(r"\bREFERENCES\s+[`\"\[]?([\w.]+)[`\"\]]?\s*(?:\([^)]*\))?[^,\n]*ON\s+DELETE\s+CASCADE", re.IGNORECASE),
    re.compile(r"ForeignKey\(\s*[\"']([\w]+)\.[\w]+[\"'][^)\n]*ondelete\s*=\s*[\"']CASCADE", re.IGNORECASE),
    re.compile(r"onDelete\s*:\s*(?:Cascade|[\"']CASCADE[\"'])[^\n]*?(?:references|=>)\s*\(?\s*(\w+)", re.IGNORECASE),
)


_DEV_TOOL_PATH_RE = re.compile(
    r"(?:^|/)(?:seeds?|seeders?|fixtures?|factories|populate\w*|clear\w*|flush\w*|reset_?db\w*|drop_?db\w*|teardown\w*|dev_?tools?|scripts/dev)(?:/|\.\w+$)",
    re.IGNORECASE,
)

# A function that deletes the data subject's own record is an erasure path, whatever
# it is called (healthchecks: `def close(request): ... user.delete()`).
_SUBJECT_DELETE_RE = re.compile(
    r"(?<![\w$])(?:request\.|self\.|ctx\.|req\.)?(?:user|account|customer|profile|member|applicant|patient|current_user|currentUser)"
    r"(?:\.objects(?:\.\w+\([^()]*\))*)?\.(?:delete|destroy|_raw_delete|hard_delete|anonymi[sz]e)\s*\(",
    re.IGNORECASE,
)


def _snake(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).lower()


def is_erasure_name(name: str) -> bool:
    return bool(_ERASURE_NAME_RE.search(_snake(name)))


def store_variants(store: str) -> Set[str]:
    """Spellings a store can appear under in code: Applicant, applicant, applicants, loan_applicant."""
    base = store.split(".")[-1]
    snake = _snake(base)
    variants = {base.lower(), snake}
    for value in list(variants):
        if value.endswith("ies"):
            variants.add(value[:-3] + "y")
        elif value.endswith("s"):
            variants.add(value[:-1])
        else:
            variants.add(value + "s")
            if value.endswith("y"):
                variants.add(value[:-1] + "ies")
    return {variant for variant in variants if len(variant) > 2}


def _mentions(text: str, variants: Iterable[str]) -> bool:
    return any(re.search(rf"(?<![\w$]){re.escape(variant)}(?![\w$])", text) for variant in variants)


# ------------------------------------------------------------------ protection
@dataclass
class Protection:
    kind: str = "none"      # encrypted | tokenised | hashed | masked | binary | none
    evidence: str = ""      # file:line that shows it

    @property
    def protected(self) -> bool:
        return self.kind in PROTECTED_KINDS


def _kind(text: str) -> str:
    for kind, pattern in _PROTECTION_KINDS:
        if pattern.search(text):
            return kind
    return "encrypted"


class _Repo:
    def __init__(self, root: Optional[Path], files: Iterable[str]):
        self.root = root.resolve() if root else None
        self._lines: Dict[str, Optional[List[str]]] = {}
        self.files = sorted(set(files))

    def lines(self, rel: str) -> Optional[List[str]]:
        if rel not in self._lines:
            try:
                path = (self.root / rel).resolve()
                path.relative_to(self.root)
                self._lines[rel] = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            except (OSError, ValueError, TypeError):
                self._lines[rel] = None
        return self._lines[rel]


def protection_index(root: Optional[Path], files: Iterable[str]) -> List[Tuple[str, int, str]]:
    """(file, line, text) for every line that wraps a value in a protecting call."""
    repo = _Repo(root, files)
    index: List[Tuple[str, int, str]] = []
    for rel in repo.files:
        for number, line in enumerate(repo.lines(rel) or [], start=1):
            code = _strip_comment(line)
            if _PROTECTING_CALL_RE.search(code) and not line.lstrip().startswith(("#", "//", "*", "/*")):
                index.append((rel, number, code))
    return index


def _strip_comment(line: str) -> str:
    """A comment saying "ciphertext" is a claim, not evidence; only code counts."""
    return re.split(r"\s(?:#|//|--)\s|^\s*(?:#|//|--)", line, maxsplit=1)[0]


def field_protection(field_name: str, declaration: str, decl_ref: str, index: List[Tuple[str, int, str]]) -> Protection:
    declaration = _strip_comment(declaration)
    if _PROTECTED_DECLARATION_RE.search(declaration):
        return Protection(_kind(declaration), decl_ref)
    variants = {field_name, _snake(field_name)}
    for rel, number, line in index:
        for match in _PROTECTING_CALL_RE.finditer(line):
            # aadhaar=encrypt_field(payload["aadhaar"])  /  encrypt(user.pan_number)  /  "aadhaar": tokenize(x)
            inside = line[match.end() : match.end() + 160]
            before = line[: match.start()]
            assigned = re.search(rf"[\"']?(?:{'|'.join(map(re.escape, variants))})[\"']?\s*(?::|=|=>)\s*$", before.rstrip()) is not None
            if assigned or _mentions(inside.split(")")[0] if ")" in inside else inside, variants):
                return Protection(_kind(match.group(1)), f"{rel}:{number}")
    if _BINARY_COLUMN_RE.search(declaration):
        return Protection("binary", decl_ref)
    return Protection()


# --------------------------------------------------------------------- erasure
@dataclass
class ErasurePath:
    name: str
    file: str
    line: int
    text: str = field(repr=False, default="")


def erasure_paths(root: Optional[Path], files: Iterable[str], extra_names: Iterable[str] = ()) -> List[ErasurePath]:
    """Functions that erase personal data, with the text of the functions they call folded in."""
    from svikruti.scanner.flows import _functions

    repo = _Repo(root, files)
    extra = {name.split(".")[-1].lower() for name in extra_names}
    defined: Dict[str, List[str]] = {}
    found: List[ErasurePath] = []
    for rel in repo.files:
        if _DEV_TOOL_PATH_RE.search(rel):
            continue  # cleardb / populatedb / seed scripts wipe whole databases; they are not an erasure path
        lines = repo.lines(rel) or []
        suffix = Path(rel).suffix.lower()
        if suffix in {".sql"}:
            # Migrations and jobs written in SQL: DELETE FROM / anonymising UPDATEs.
            for number, line in enumerate(lines, start=1):
                if re.search(r"\bDELETE\s+FROM\b|\bTRUNCATE\b", line, re.IGNORECASE):
                    found.append(ErasurePath("sql:delete", rel, number, line))
            continue
        # Classes named for erasure (Django/GraphQL mutations such as AccountDelete, CustomerErasureJob).
        for number, line in enumerate(lines):
            match = re.match(r"^(\s*)(?:export\s+)?(?:default\s+)?class\s+(\w+)", line)
            if not match or not is_erasure_name(match.group(2)):
                continue
            indent, end = len(match.group(1)), len(lines)
            for offset in range(number + 1, len(lines)):
                text = lines[offset]
                if text.strip() and len(text) - len(text.lstrip()) <= indent and not text.lstrip().startswith(("}", ")", "@")):
                    end = offset
                    break
            found.append(ErasurePath(match.group(2), rel, number + 1, "\n".join(lines[number:end])))
        for function in _functions(lines, suffix):
            body = "\n".join(lines[function.start : function.end + 1])
            defined.setdefault(function.name, []).append(body)
            if is_erasure_name(function.name) or function.name.lower() in extra or _SUBJECT_DELETE_RE.search(body):
                found.append(ErasurePath(function.name, rel, function.start + 1, body))
    # One level of calls: delete_user() -> _delete_kyc_records() -> Applicant.objects...
    for path in found:
        called = set(re.findall(r"(?<![\w$.])([A-Za-z_$][\w$]*)\s*\(", path.text)) | set(re.findall(r"\.([A-Za-z_$][\w$]*)\s*\(", path.text))
        extra_text = [body for name in called if name != path.name for body in defined.get(name, [])[:3]]
        path.text = path.text + "\n" + "\n".join(extra_text)
    return found


def cascades(root: Optional[Path], store_files: Dict[str, Tuple[str, int]]) -> Dict[str, Set[str]]:
    """store -> parents it cascades from on delete, read from the store's own declaration."""
    repo = _Repo(root, [rel for rel, _ in store_files.values()])
    out: Dict[str, Set[str]] = {}
    for store, (rel, line) in store_files.items():
        lines = repo.lines(rel) or []
        block = "\n".join(lines[_declaration_bounds(lines, line)[0] : _declaration_bounds(lines, line)[1]])
        for pattern in _CASCADE_RES:
            for match in pattern.finditer(block):
                parent = match.group(1).split(".")[-1]
                if parent.lower() not in store_variants(store):
                    out.setdefault(store, set()).add(parent)
    return out


def _is_container_header(text: str) -> bool:
    return any(pattern.search(text) for pattern in _CONTAINER_RES)


def _declaration_bounds(lines: List[str], line: int) -> Tuple[int, int]:
    """[start, end) of the table / model declaration that contains 1-based ``line``."""
    start = 0
    for index in range(min(line, len(lines)) - 1, max(line - 200, 0) - 1, -1):
        if _is_container_header(lines[index]):
            start = index
            break
    end = len(lines)
    for index in range(start + 1, min(start + 300, len(lines))):
        if _is_container_header(lines[index]):
            end = index
            break
    return start, end


def is_persistent_store(rel: str, header: str) -> bool:
    """Is this table / model actually stored, rather than a form, DTO or API type?"""
    if _PERSISTENT_HEADER_RE.search(header):
        return True
    if _TRANSIENT_HEADER_RE.search(header):
        return False
    if rel.lower().endswith((".sql", ".prisma")):
        return True
    return bool(_PERSISTENT_PATH_RE.search(rel)) and not _TRANSIENT_PATH_RE.search(rel)


def store_header(lines: List[str], line: int) -> str:
    start, _ = _declaration_bounds(lines, line)
    return lines[start] if lines else ""


def _erases(text: str, variants: Iterable[str]) -> bool:
    """Does this code delete or overwrite the store, rather than merely mention it?"""
    lowered = text.lower()
    for variant in variants:
        v = re.escape(variant)
        if re.search(
            # Applicant.objects.filter(id=x).delete()  /  user.delete()  /  User.query.filter_by(id=x).update({...})
            rf"(?<![\w$]){v}s?(?:\.\w+(?:\((?:[^()]|\([^()]*\))*\))?)*?\.(?:_raw_)?(?:delete|destroy|remove|update|anonymi[sz]e|erase|purge|soft_delete|hard_delete)\w*\s*\(?"
            rf"|\b(?:delete\s+from|update|truncate(?:\s+table)?)\s+[`\"\[]?{v}\b"
            rf"|(?<![\w$]){v}\.\w+\s*=(?!=)"
            rf"|\.{v}s?\.(?:delete|destroy|deletemany|update|updatemany|remove)\w*\("
            rf"|(?:delete|destroy|remove|anonymi[sz]e|erase)\w*\(\s*{v}s?\b",
            lowered,
        ):
            return True
    return False


def erasure_coverage(
    stores: Dict[str, Tuple[str, int]],
    paths: List[ErasurePath],
    retained: Dict[str, str],
    cascade_map: Dict[str, Set[str]],
) -> Dict[str, str]:
    """store -> 'erased by name (file:line)' | 'cascade from X' | 'retained: reason' | ''."""
    retained_lower = {key.lower(): value for key, value in retained.items()}
    coverage: Dict[str, str] = {}
    for store in stores:
        reason = retained_lower.get(store.lower())
        if reason:
            coverage[store] = f"retained: {reason}"
            continue
        variants = store_variants(store)
        hit = next((path for path in paths if _erases(path.text, variants)), None)
        coverage[store] = f"reached by {path_label(hit)}" if hit else ""
    # Cascades, iterated so a chain of cascades resolves.
    for _ in range(3):
        changed = False
        for store, parents in cascade_map.items():
            if coverage.get(store):
                continue
            for parent in parents:
                parent_store = next((name for name in coverage if parent.lower() in store_variants(name)), None)
                if parent_store and coverage.get(parent_store, "").startswith(("reached", "cascade")):
                    coverage[store] = f"cascade from {parent_store}"
                    changed = True
                    break
                if parent_store is None:
                    # The parent holds no detected personal data (e.g. Django's User), but deleting it still cascades.
                    hit = next((path for path in paths if _erases(path.text, store_variants(parent))), None)
                    if hit:
                        coverage[store] = f"cascade from {parent} ({path_label(hit)})"
                        changed = True
                        break
        if not changed:
            break
    return coverage


def path_label(path: ErasurePath) -> str:
    return f"{path.name}() ({path.file}:{path.line})" if not path.name.startswith("sql:") else f"DELETE in {path.file}:{path.line}"
