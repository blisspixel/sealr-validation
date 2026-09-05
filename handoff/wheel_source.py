#!/usr/bin/env python3
"""Install a digest-bound staged wheel through PyPA installer 1.0.1."""

from __future__ import annotations

import base64
import csv
import hashlib
import hmac
import importlib
import importlib.metadata
import io
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any, Callable, Iterable


SCHEMA = "sealr.pypa-wheel-source.v1"
POETRY_SCHEMA = "sealr.pypa-wheel-source.v2"
REPORT_SCHEMA = "sealr.pypa-wheel-source-report.v1"
ADAPTER = "pypa-installer-1.0.1-wheel-source"
INSTALLER_VERSION = "1.0.1"
INSTALLER_WHEEL_SHA256 = (
    "011d045df8b954ced7dde3a7e42ae4418da40ecda7990f2d11d5ed7c146fd98b"
)
INSTALLER_RECORD_SHA256 = (
    "d5afb5fcf8e07ca62220e45458c9d909dddc3743fdadad5018ffe40651adb031"
)
INTERPRETER = "/usr/bin/python3"
TARGET_MODEL = "pypa-installer-1.0.1-linux-posix"
INSTALLER_POLICY = "separate-roots-no-bytecode-no-overwrite-v1"
POETRY_TARGET_MODEL = "poetry-2.4.2-installer-1.0.1-linux-posix"
POETRY_INSTALLER_POLICY = (
    "poetry-2.4.2-cpython-3.12-venv-no-bytecode-no-overwrite-v1"
)
POETRY_INSTALLER_METADATA = "Poetry 2.4.2"
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_REPORT_BYTES = 16 * 1024 * 1024
MAX_MEMBERS = 65_536
MAX_MEMBER_BYTES = 16 * 1024 * 1024
MAX_TOTAL_MEMBER_BYTES = 64 * 1024 * 1024
MAX_DIST_INFO_BYTES = 16 * 1024 * 1024
MAX_INSTALLER_BYTES = 32 * 1024 * 1024
MAX_OUTPUT_FILES = 131_072
MAX_OUTPUT_BYTES = 128 * 1024 * 1024
MAX_INTERPRETER_REPORT_BYTES = 4096
SCHEMES = ("purelib", "platlib", "scripts", "headers", "data")
HEX_SHA256 = re.compile(r"[0-9a-f]{64}")
RECORD_SHA256 = re.compile(r"sha256=([A-Za-z0-9_-]{43})")
DECIMAL = re.compile(r"0|[1-9][0-9]*")
MANIFEST_V1_KEYS = {
    "schema",
    "adapter",
    "installer_version",
    "installer_wheel_sha256",
    "canonical_receipt_sha256",
    "artifact_sha256",
    "install_plan_sha256",
    "distribution",
    "version",
    "dist_info_dir",
    "data_dir",
    "interpreter",
    "target_model",
    "installer_policy",
    "members",
}
MANIFEST_V2_KEYS = MANIFEST_V1_KEYS | {"additional_installer", "destination_model"}
MEMBER_KEYS = {
    "index",
    "path",
    "blob",
    "sha256",
    "size",
    "record_hash",
    "record_size",
    "executable",
}


class HandoffError(ValueError):
    """A closed-contract, source, or installation failure."""


def _fail(detail: str) -> None:
    raise HandoffError(detail)


def _audit_hook(event: str, args: tuple[Any, ...]) -> None:
    if event != "open" or not args:
        return
    value = args[0]
    if isinstance(value, bytes):
        value = os.fsdecode(value)
    if isinstance(value, str) and value.casefold().endswith(".whl"):
        _fail("opening wheel archives is forbidden in the WheelSource adapter")


sys.addaudithook(_audit_hook)
sys.dont_write_bytecode = True


def _prove_wheel_open_denied() -> None:
    try:
        with open("sealr-wheel-open-audit-probe.whl", "rb"):
            pass
    except HandoffError as error:
        if "forbidden" not in str(error):
            raise
    else:
        _fail("the active audit hook allowed a wheel open")


def _duplicate_safe_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"JSON contains duplicate key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    _fail(f"JSON contains forbidden number {value}")


def _exact_object(value: Any, keys: set[str], where: str) -> dict[str, Any]:
    if type(value) is not dict:
        _fail(f"{where} must be an object")
    actual = set(value)
    if actual != keys:
        _fail(
            f"{where} keys disagree: missing={sorted(keys - actual)}, "
            f"unexpected={sorted(actual - keys)}"
        )
    return value


def _string(value: Any, where: str, maximum: int = 4096) -> str:
    if type(value) is not str or not value:
        _fail(f"{where} must be a nonempty string")
    if len(value.encode("utf-8")) > maximum or "\x00" in value:
        _fail(f"{where} exceeds its UTF-8 cap or contains NUL")
    return value


def _integer(value: Any, where: str, maximum: int = (1 << 64) - 1) -> int:
    if type(value) is not int or value < 0 or value > maximum:
        _fail(f"{where} must be an unsigned integer no greater than {maximum}")
    return value


def _hex_sha256(value: Any, where: str) -> str:
    text = _string(value, where, 64)
    if HEX_SHA256.fullmatch(text) is None:
        _fail(f"{where} must be a lowercase hexadecimal SHA-256 digest")
    return text


def _canonical_path(value: Any, where: str) -> str:
    text = _string(value, where)
    if text.startswith("/") or "\\" in text:
        _fail(f"{where} is not a relative POSIX path")
    if any(part in ("", ".", "..") for part in text.split("/")):
        _fail(f"{where} contains a forbidden path component")
    return text


def _one_component(value: Any, suffix: str, where: str) -> str:
    text = _canonical_path(value, where)
    if "/" in text or not text.endswith(suffix):
        _fail(f"{where} must be one component ending in {suffix}")
    return text


def _open_regular(path: Path) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(descriptor)
        _fail(f"single-link regular file required: {path}")
    return descriptor, info


def _read_regular(path: Path, maximum: int, expected_size: int | None = None) -> bytes:
    descriptor, before = _open_regular(path)
    try:
        if before.st_size > maximum:
            _fail(f"file exceeds its byte cap: {path}")
        if expected_size is not None and before.st_size != expected_size:
            _fail(f"file size disagrees with the manifest: {path.name}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            encoded = stream.read(maximum + 1)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    stable = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if not stable or len(encoded) != before.st_size:
        _fail(f"file changed while it was read: {path}")
    return encoded


def _require_trusted_directory(
    path: Path, where: str, *, allow_root_sticky: bool = False
) -> os.stat_result:
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        _fail(f"{where} must be a real directory")
    if info.st_uid not in (0, os.geteuid()):
        _fail(f"{where} has an untrusted owner")
    writable = info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
    trusted_sticky = (
        allow_root_sticky
        and info.st_uid == 0
        and bool(info.st_mode & stat.S_ISVTX)
    )
    if writable and not trusted_sticky:
        _fail(f"{where} permits untrusted namespace mutation")
    return info


def _trusted_absolute_parent(path: Path, where: str) -> Path:
    absolute = path.absolute()
    parent = absolute.parent
    current = Path(parent.anchor)
    _require_trusted_directory(current, f"{where} ancestor", allow_root_sticky=True)
    for component in parent.parts[1:]:
        current /= component
        _require_trusted_directory(
            current, f"{where} ancestor", allow_root_sticky=True
        )
    return absolute


def _verify_installer_root(import_root: Path) -> Path:
    import_root = _trusted_absolute_parent(import_root, "installer import root")
    root_info = os.lstat(import_root)
    if stat.S_ISLNK(root_info.st_mode) or not stat.S_ISDIR(root_info.st_mode):
        _fail("installer import root must be a real directory")
    if import_root.name.casefold().endswith(".whl"):
        _fail("installer import root must be extracted, not a wheel archive")
    root = import_root
    _require_trusted_directory(root, "installer import root")

    record_path = "installer-1.0.1.dist-info/RECORD"
    record_bytes = _read_regular(root / record_path, MAX_DIST_INFO_BYTES)
    if not hmac.compare_digest(
        hashlib.sha256(record_bytes).hexdigest(), INSTALLER_RECORD_SHA256
    ):
        _fail("installer root RECORD disagrees with the pinned wheel")
    try:
        rows = list(csv.reader(io.StringIO(record_bytes.decode("utf-8"), newline="")))
    except (UnicodeDecodeError, csv.Error) as error:
        _fail(f"installer root RECORD is invalid: {error}")

    expected: dict[str, tuple[str, int] | None] = {}
    for offset, row in enumerate(rows):
        where = f"installer RECORD row {offset + 1}"
        if len(row) != 3:
            _fail(f"{where} must contain exactly three fields")
        path = _canonical_path(row[0], f"{where} path")
        if path in expected:
            _fail(f"{where} duplicates {path}")
        if path == record_path:
            if row[1] or row[2]:
                _fail("installer RECORD self-row must have empty hash and size")
            expected[path] = None
            continue
        match = RECORD_SHA256.fullmatch(row[1])
        if match is None or DECIMAL.fullmatch(row[2]) is None:
            _fail(f"{where} must contain a SHA-256 hash and canonical size")
        expected[path] = (match.group(1), int(row[2]))
    if expected.get(record_path, object()) is not None:
        _fail("installer RECORD must contain one self-row")

    expected_directories = {
        "/".join(path.split("/")[:depth])
        for path in expected
        for depth in range(1, len(path.split("/")))
    }
    actual: set[str] = set()
    pending: list[tuple[Path, str]] = [(root, "")]
    total = 0
    while pending:
        directory, prefix = pending.pop()
        _require_trusted_directory(directory, "installer tree directory")
        with os.scandir(directory) as entries:
            for entry in entries:
                path = Path(entry.path)
                relative = f"{prefix}/{entry.name}" if prefix else entry.name
                _canonical_path(relative, "installer tree path")
                if entry.is_symlink():
                    _fail(f"installer tree contains a symbolic link: {path}")
                if entry.is_dir(follow_symlinks=False):
                    if relative not in expected_directories:
                        _fail(f"installer tree contains an unexpected directory: {relative}")
                    pending.append((path, relative))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    _fail(f"installer tree contains a non-regular file: {path}")
                if relative not in expected:
                    _fail(f"installer tree contains an unexpected file: {relative}")
                info = entry.stat(follow_symlinks=False)
                if info.st_uid not in (0, os.geteuid()) or info.st_mode & (
                    stat.S_IWGRP | stat.S_IWOTH
                ):
                    _fail(f"installer tree file has unsafe ownership or mode: {path}")
                actual.add(relative)
                total += info.st_size
                if total > MAX_INSTALLER_BYTES:
                    _fail("installer tree exceeds its aggregate byte cap")
    if actual != set(expected):
        _fail("installer tree file set disagrees with the pinned RECORD")

    for relative, binding in expected.items():
        if binding is None:
            continue
        digest, size = binding
        data = _read_regular(root / relative, MAX_INSTALLER_BYTES, size)
        encoded = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
        if not hmac.compare_digest(encoded.decode("ascii"), digest):
            _fail(f"installer tree content disagrees with RECORD: {relative}")
    return root


def _load_manifest(path: Path, expected_digest: str) -> dict[str, Any]:
    digest = _hex_sha256(expected_digest, "expected manifest SHA-256")
    encoded = _read_regular(path, MAX_MANIFEST_BYTES)
    if not hmac.compare_digest(hashlib.sha256(encoded).hexdigest(), digest):
        _fail("raw manifest bytes disagree with the expected SHA-256")
    try:
        value = json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_duplicate_safe_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(f"manifest is not strict UTF-8 JSON: {error}")
    if type(value) is not dict:
        _fail("manifest must be an object")
    schema = value.get("schema")
    if schema == SCHEMA:
        return _exact_object(value, MANIFEST_V1_KEYS, "manifest")
    if schema == POETRY_SCHEMA:
        return _exact_object(value, MANIFEST_V2_KEYS, "manifest")
    _fail("manifest.schema is unsupported")


def _validate_manifest(
    manifest: dict[str, Any], expected_receipt: str
) -> tuple[list[dict[str, Any]], str]:
    expected = {
        "adapter": ADAPTER,
        "installer_version": INSTALLER_VERSION,
        "installer_wheel_sha256": INSTALLER_WHEEL_SHA256,
    }
    for key, value in expected.items():
        if manifest[key] != value:
            _fail(f"manifest.{key} must equal {value!r}")

    if manifest["schema"] == SCHEMA:
        target = (
            manifest["target_model"],
            manifest["installer_policy"],
            None,
            "fresh-separate-roots-v1",
        )
        manifest["additional_installer"] = None
        manifest["destination_model"] = "fresh-separate-roots-v1"
    else:
        target = (
            manifest["target_model"],
            manifest["installer_policy"],
            manifest["additional_installer"],
            manifest["destination_model"],
        )
    allowed_targets = (
        (TARGET_MODEL, INSTALLER_POLICY, None, "fresh-separate-roots-v1"),
        (
            POETRY_TARGET_MODEL,
            POETRY_INSTALLER_POLICY,
            POETRY_INSTALLER_METADATA,
            "poetry-2.4.2-cpython-3.12-venv-v1",
        ),
    )
    if target not in allowed_targets:
        _fail("manifest target model and installer policy combination is unsupported")
    interpreter = _string(manifest["interpreter"], "manifest.interpreter")
    if target == allowed_targets[0] and interpreter != INTERPRETER:
        _fail(f"manifest.interpreter must equal {INTERPRETER!r}")
    if target == allowed_targets[1] and not Path(interpreter).is_absolute():
        _fail("Poetry target interpreter must be absolute")

    receipt = _hex_sha256(expected_receipt, "expected canonical receipt SHA-256")
    if _hex_sha256(
        manifest["canonical_receipt_sha256"],
        "manifest.canonical_receipt_sha256",
    ) != receipt:
        _fail("manifest canonical receipt SHA-256 disagrees with the expected value")
    _hex_sha256(manifest["artifact_sha256"], "manifest.artifact_sha256")
    _hex_sha256(manifest["install_plan_sha256"], "manifest.install_plan_sha256")
    _string(manifest["distribution"], "manifest.distribution")
    _string(manifest["version"], "manifest.version")
    dist_info = _one_component(
        manifest["dist_info_dir"], ".dist-info", "manifest.dist_info_dir"
    )
    _one_component(manifest["data_dir"], ".data", "manifest.data_dir")

    values = manifest["members"]
    if type(values) is not list or not values or len(values) > MAX_MEMBERS:
        _fail(f"manifest.members must contain 1..={MAX_MEMBERS} items")
    members: list[dict[str, Any]] = []
    indices: set[int] = set()
    paths: set[str] = set()
    blobs: set[str] = set()
    total = 0
    previous_index = -1
    record_path = f"{dist_info}/RECORD"
    signature_paths = {f"{record_path}.jws", f"{record_path}.p7s"}
    for offset, raw in enumerate(values):
        where = f"manifest.members[{offset}]"
        member = _exact_object(raw, MEMBER_KEYS, where)
        index = _integer(member["index"], f"{where}.index")
        path = _canonical_path(member["path"], f"{where}.path")
        blob = _one_component(member["blob"], ".bin", f"{where}.blob")
        digest = _hex_sha256(member["sha256"], f"{where}.sha256")
        size = _integer(member["size"], f"{where}.size", MAX_MEMBER_BYTES)
        record_hash = member["record_hash"]
        record_size = member["record_size"]
        if type(record_hash) is not str or type(record_size) is not str:
            _fail(f"{where} RECORD fields must be strings")
        if type(member["executable"]) is not bool:
            _fail(f"{where}.executable must be a boolean")
        if index <= previous_index:
            _fail("manifest members must be ordered by increasing source index")
        previous_index = index
        if index in indices or path in paths or blob in blobs:
            _fail(f"{where} duplicates an index, path, or blob")
        indices.add(index)
        paths.add(path)
        blobs.add(blob)
        total += size
        if total > MAX_TOTAL_MEMBER_BYTES:
            _fail("manifest members exceed the aggregate byte cap")

        if path == record_path or path in signature_paths:
            if record_hash or record_size:
                _fail(f"{where} RECORD fields must be empty")
        else:
            match = RECORD_SHA256.fullmatch(record_hash)
            if match is None or DECIMAL.fullmatch(record_size) is None:
                _fail(f"{where} has invalid RECORD hash or size text")
            encoded_digest = (
                base64.urlsafe_b64encode(bytes.fromhex(digest))
                .rstrip(b"=")
                .decode("ascii")
            )
            if match.group(1) != encoded_digest or record_size != str(size):
                _fail(f"{where} RECORD fields disagree with staged evidence")
        members.append(member)
    if record_path not in paths:
        _fail("manifest members do not contain the selected RECORD")
    return members, receipt


def _load_member_bytes(
    manifest_path: Path, members: list[dict[str, Any]]
) -> tuple[dict[str, Any], ...]:
    root = manifest_path.parent / "members"
    info = os.lstat(root)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        _fail("staged members root must be a real directory")
    expected = {member["blob"] for member in members}
    with os.scandir(root) as entries:
        actual = {entry.name for entry in entries}
    if actual != expected:
        _fail(
            "staged blob set disagrees with the manifest: "
            f"missing={sorted(expected - actual)}, unexpected={sorted(actual - expected)}"
        )
    prepared = []
    for member in members:
        data = _read_regular(root / member["blob"], MAX_MEMBER_BYTES, member["size"])
        if hashlib.sha256(data).hexdigest() != member["sha256"]:
            _fail(f"staged member evidence mismatch: {member['path']}")
        prepared.append({**member, "data": data})
    return tuple(prepared)


def _load_installer(import_root: Path) -> tuple[Any, Any, type, type, Callable[..., Any]]:
    root = _verify_installer_root(import_root)
    sys.path.insert(0, str(root))
    package = importlib.import_module("installer")
    package_file = Path(package.__file__).resolve(strict=True)
    try:
        package_file.relative_to(root)
    except ValueError:
        _fail("installer was not imported from the supplied root")
    distributions = [
        item
        for item in importlib.metadata.distributions(path=[str(root)])
        if item.metadata.get("Name", "").casefold() == "installer"
    ]
    if len(distributions) != 1 or distributions[0].version != INSTALLER_VERSION:
        _fail(f"installer root must contain exactly installer {INSTALLER_VERSION}")
    destinations = importlib.import_module("installer.destinations")
    records = importlib.import_module("installer.records")
    sources = importlib.import_module("installer.sources")
    return (
        package.install,
        destinations.SchemeDictionaryDestination,
        sources.WheelSource,
        records.RecordEntry,
        records.parse_record_file,
    )


def _source_type(
    wheel_source_base: type,
    record_entry_type: type,
    parse_record_file: Callable[..., Iterable[Any]],
) -> type:
    class StagedWheelSource(wheel_source_base):
        validation_error = HandoffError

        def __init__(self, manifest: dict[str, Any], members: tuple[dict[str, Any], ...]):
            super().__init__(manifest["distribution"], manifest["version"])
            self._members = members
            self._by_path = {member["path"]: member for member in members}
            self._dist_info_dir = manifest["dist_info_dir"]
            self._data_dir = manifest["data_dir"]

        @property
        def dist_info_dir(self) -> str:
            return self._dist_info_dir

        @property
        def data_dir(self) -> str:
            return self._data_dir

        @property
        def dist_info_filenames(self) -> list[str]:
            prefix = f"{self.dist_info_dir}/"
            return sorted(
                path[len(prefix) :]
                for path in self._by_path
                if path.startswith(prefix) and "/" not in path[len(prefix) :]
            )

        def read_dist_info(self, filename: str) -> str:
            if not filename or "/" in filename or "\\" in filename or filename in (".", ".."):
                _fail("invalid dist-info filename request")
            member = self._by_path.get(f"{self.dist_info_dir}/{filename}")
            if member is None:
                _fail(f"missing dist-info member: {filename}")
            if member["size"] > MAX_DIST_INFO_BYTES:
                _fail("dist-info member exceeds its byte cap")
            return member["data"].decode("utf-8")

        def validate_record(self) -> None:
            record_path = f"{self.dist_info_dir}/RECORD"
            if record_path not in self._by_path:
                _fail("staged wheel is missing RECORD")
            rows = list(parse_record_file(self.read_dist_info("RECORD").splitlines()))
            by_path: dict[str, tuple[str, str]] = {}
            for row in rows:
                if len(row) != 3 or any(type(item) is not str for item in row):
                    _fail("RECORD parser returned an invalid row")
                if row[0] in by_path:
                    _fail(f"RECORD contains duplicate path: {row[0]}")
                by_path[row[0]] = (row[1], row[2])
            signatures = {f"{record_path}.jws", f"{record_path}.p7s"}
            for member in self._members:
                path = member["path"]
                if path in signatures:
                    if path in by_path:
                        _fail("legacy RECORD signature must remain outside RECORD")
                    continue
                expected = (member["record_hash"], member["record_size"])
                if by_path.pop(path, None) != expected:
                    _fail(f"RECORD binding mismatch: {path}")
                entry = record_entry_type.from_elements(path, *expected)
                if path != record_path and not entry.validate_stream(io.BytesIO(member["data"])):
                    _fail(f"RECORD content validation failed: {path}")
            if by_path:
                _fail(f"RECORD references unstaged paths: {sorted(by_path)}")

        def get_contents(self) -> Iterable[tuple[Any, Any, bool]]:
            for member in self._members:
                record = (
                    member["path"],
                    member["record_hash"],
                    member["record_size"],
                )
                with io.BytesIO(member["data"]) as stream:
                    yield record, stream, member["executable"]

    return StagedWheelSource


def _consume_source(source: Any) -> list[tuple[Any, str, int, bool]]:
    result = []
    for record, stream, executable in source.get_contents():
        if (
            type(record) is not tuple
            or len(record) != 3
            or any(type(item) is not str for item in record)
            or type(executable) is not bool
        ):
            _fail("WheelSource returned an invalid content element")
        digest = hashlib.sha256()
        size = 0
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            size += len(chunk)
        result.append((record, digest.hexdigest(), size, executable))
    return result


def _prepare_destination(root: Path, manifest: dict[str, Any]) -> dict[str, str]:
    root = _trusted_absolute_parent(root, "output root")
    if manifest["destination_model"] == "fresh-separate-roots-v1":
        if root.exists() or root.is_symlink():
            _fail("output root already exists; exclusive installation is required")
        root.mkdir(mode=0o700)
        created = os.lstat(root)
        if (
            stat.S_ISLNK(created.st_mode)
            or not stat.S_ISDIR(created.st_mode)
            or created.st_uid != os.geteuid()
            or created.st_mode & (stat.S_IRWXG | stat.S_IRWXO)
        ):
            _fail("output root was not created as an effective-user-private directory")
        scheme_dict = {}
        resolved = set()
        for scheme in SCHEMES:
            path = root / scheme
            path.mkdir(mode=0o700)
            value = path.resolve(strict=True)
            if value in resolved:
                _fail("scheme roots must be distinct")
            resolved.add(value)
            scheme_dict[scheme] = str(value)
        return scheme_dict

    created = _require_trusted_directory(root, "Poetry virtual environment root")
    if created.st_uid != os.geteuid() or created.st_mode & (
        stat.S_IWGRP | stat.S_IWOTH
    ):
        _fail("Poetry virtual environment root must deny group and other writes")
    purelib = root / "lib/python3.12/site-packages"
    scripts = root / "bin"
    _require_trusted_directory(purelib, "Poetry virtual environment site-packages")
    _require_trusted_directory(scripts, "Poetry virtual environment scripts")
    interpreter = Path(manifest["interpreter"]).absolute()
    if interpreter != root / "bin/python":
        _fail("Poetry target interpreter disagrees with the virtual environment")
    interpreter_info = os.lstat(interpreter)
    if not (stat.S_ISREG(interpreter_info.st_mode) or stat.S_ISLNK(interpreter_info.st_mode)):
        _fail("Poetry target interpreter must be a file or symbolic link")
    _verify_poetry_interpreter(root, interpreter)
    return {
        "purelib": str(purelib),
        "platlib": str(purelib),
        "scripts": str(scripts),
        "headers": str(
            root
            / "include/site/python3.12"
            / manifest["distribution"]
        ),
        "data": str(root),
    }


def _verify_poetry_interpreter(root: Path, interpreter: Path) -> None:
    script = (
        "import json, pathlib, sys\n"
        "print(json.dumps({"
        "'implementation': sys.implementation.name,"
        "'version': list(sys.version_info[:3]),"
        "'prefix': str(pathlib.Path(sys.prefix).resolve()),"
        "'executable': str(pathlib.Path(sys.executable).absolute())"
        "}, sort_keys=True, separators=(',', ':')))\n"
    )
    try:
        result = subprocess.run(
            [str(interpreter), "-I", "-B", "-c", script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        _fail(f"Poetry target interpreter identity failed: {error}")
    if result.returncode != 0:
        detail = result.stderr[:MAX_INTERPRETER_REPORT_BYTES].decode(
            "utf-8", errors="replace"
        )
        _fail(f"Poetry target interpreter identity failed: {detail}")
    if len(result.stdout) > MAX_INTERPRETER_REPORT_BYTES:
        _fail("Poetry target interpreter identity report exceeds its cap")
    try:
        identity = json.loads(
            result.stdout.decode("utf-8"),
            object_pairs_hook=_duplicate_safe_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        _fail(f"Poetry target interpreter identity is not strict JSON: {error}")
    identity = _exact_object(
        identity,
        {"implementation", "version", "prefix", "executable"},
        "Poetry target interpreter identity",
    )
    if identity != {
        "implementation": "cpython",
        "version": [3, 12, sys.version_info.micro],
        "prefix": str(root.resolve(strict=True)),
        "executable": str(interpreter.absolute()),
    }:
        _fail("Poetry target interpreter is not this exact CPython 3.12 environment")


def _validate_poetry_output_target(
    output_root: Path,
    scheme_dict: dict[str, str],
    scheme: str,
    raw_path: str,
    physical: set[str],
) -> tuple[str, Path]:
    if scheme not in SCHEMES:
        _fail(f"installer wrote an unknown scheme: {scheme}")
    relative = _canonical_path(raw_path, "installer-written output path")
    scheme_root = Path(scheme_dict[scheme]).absolute()
    target = Path(os.path.abspath(scheme_root / relative))
    if target != scheme_root and scheme_root not in target.parents:
        _fail(f"installer output escaped its scheme root: {scheme}/{relative}")
    root = output_root.resolve(strict=True)
    try:
        target_relative = target.relative_to(root)
    except ValueError:
        _fail(f"installer output escaped the Poetry environment: {scheme}/{relative}")
    current = root
    components = list(target_relative.parts)
    for offset, component in enumerate(components):
        current /= component
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            _fail(f"installer output crosses a symbolic link: {scheme}/{relative}")
        if offset < len(components) - 1:
            if not stat.S_ISDIR(info.st_mode):
                _fail(f"installer output ancestor is not a directory: {scheme}/{relative}")
            _require_trusted_directory(current, "Poetry output ancestor")
        else:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                _fail(f"existing installer target is not a single-link regular file: {scheme}/{relative}")
            if info.st_uid != os.geteuid() or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                _fail(f"existing installer target is not effective-user-controlled: {scheme}/{relative}")
    physical_key = str(target)
    if physical_key in physical:
        _fail(f"installer outputs alias one physical target: {scheme}/{relative}")
    for prior_key in physical:
        prior = Path(prior_key)
        if target in prior.parents or prior in target.parents:
            _fail(
                "installer outputs have a physical file-ancestor conflict: "
                f"{scheme}/{relative}"
            )
    physical.add(physical_key)
    return relative, target


def _preflight_destination_type(
    destination_type: type[Any],
    record_entry_type: type[Any],
    output_root: Path,
) -> type[Any]:
    class PreflightDestination(destination_type):
        def __init__(self: Any, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._sealr_physical: set[str] = set()
            self._sealr_count = 0
            self._sealr_total = 0

        def write_to_fs(
            self: Any,
            scheme: str,
            path: str,
            stream: Any,
            is_executable: bool,
        ) -> Any:
            del is_executable
            relative, _target = _validate_poetry_output_target(
                output_root,
                self.scheme_dict,
                scheme,
                path,
                self._sealr_physical,
            )
            if self._sealr_count >= MAX_OUTPUT_FILES:
                _fail("installer outputs exceed the file-count cap")
            digest = hashlib.sha256()
            size = 0
            while chunk := stream.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_OUTPUT_BYTES - self._sealr_total:
                    _fail("installer outputs exceed the aggregate byte cap")
                digest.update(chunk)
            self._sealr_count += 1
            self._sealr_total += size
            encoded = base64.urlsafe_b64encode(digest.digest()).rstrip(b"=").decode("ascii")
            return record_entry_type.from_elements(
                relative,
                f"sha256={encoded}",
                str(size),
            )

        def write_script(
            self: Any,
            name: str,
            module: str,
            attr: str,
            section: str,
        ) -> Any:
            script_type = destination_type.write_script.__globals__["Script"]
            script = script_type(name, module, attr, section)
            script_name, data = script.generate(self.interpreter, self.script_kind)
            with io.BytesIO(data) as stream:
                return self.write_to_fs(
                    "scripts",
                    script_name,
                    stream,
                    is_executable=True,
                )

    return PreflightDestination


def _tracking_destination_type(
    destination_type: type[Any],
    writes: list[tuple[str, str, bool]],
    output_root: Path,
) -> type[Any]:
    class TrackingDestination(destination_type):
        def __init__(self: Any, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self._sealr_physical: set[str] = set()

        def write_to_fs(
            self: Any,
            scheme: str,
            path: str,
            stream: Any,
            is_executable: bool,
        ) -> Any:
            if len(writes) >= MAX_OUTPUT_FILES:
                _fail("installer outputs exceed the file-count cap")
            _validate_poetry_output_target(
                output_root,
                self.scheme_dict,
                scheme,
                path,
                self._sealr_physical,
            )
            record = super().write_to_fs(scheme, path, stream, is_executable)
            writes.append((scheme, path, is_executable))
            return record

    return TrackingDestination


def _enumerate_written_outputs(
    destination: Any, writes: list[tuple[str, str, bool]]
) -> list[dict[str, Any]]:
    outputs = []
    logical = set()
    physical = set()
    total = 0
    for scheme, raw_path, requested_executable in writes:
        if scheme not in SCHEMES:
            _fail(f"installer wrote an unknown scheme: {scheme}")
        path_text = _canonical_path(raw_path, "installer-written output path")
        key = (scheme, path_text)
        if key in logical:
            _fail(f"installer wrote an output more than once: {scheme}/{path_text}")
        logical.add(key)
        scheme_root = Path(destination.scheme_dict[scheme]).resolve(strict=True)
        path = scheme_root / path_text
        resolved_parent = path.parent.resolve(strict=True)
        if resolved_parent != scheme_root and scheme_root not in resolved_parent.parents:
            _fail(f"installer output escaped its scheme root: {scheme}/{path_text}")
        physical_key = (resolved_parent / path.name).as_posix()
        if physical_key in physical:
            _fail(f"installer outputs alias one physical target: {scheme}/{path_text}")
        physical.add(physical_key)
        digest, size, mode = _hash_regular(path, MAX_OUTPUT_BYTES - total)
        total += size
        executable = bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))
        if executable != requested_executable:
            _fail(f"installer output mode disagrees: {scheme}/{path_text}")
        outputs.append(
            {
                "scheme": scheme,
                "relative_path": path_text,
                "sha256": digest,
                "size": size,
                "executable": executable,
            }
        )
    outputs.sort(key=lambda item: (SCHEMES.index(item["scheme"]), item["relative_path"]))
    return outputs


def _hash_regular(path: Path, remaining: int) -> tuple[str, int, int]:
    descriptor, before = _open_regular(path)
    try:
        if before.st_nlink != 1:
            _fail(f"installed output has multiple hard links: {path}")
        if before.st_size > remaining:
            _fail("installed outputs exceed the aggregate byte cap")
        digest = hashlib.sha256()
        size = 0
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while chunk := stream.read(1024 * 1024):
                digest.update(chunk)
                size += len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    stable = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    if not stable or size != before.st_size:
        _fail(f"installed file changed while it was read: {path}")
    return digest.hexdigest(), size, before.st_mode


def _enumerate_outputs(root: Path) -> list[dict[str, Any]]:
    with os.scandir(root) as entries:
        top = {entry.name for entry in entries}
    if top != set(SCHEMES):
        _fail("output root does not contain exactly the five scheme directories")
    outputs = []
    total = 0
    for scheme in SCHEMES:
        scheme_root = root / scheme
        stack: list[tuple[Path, str]] = [(scheme_root, "")]
        while stack:
            directory, prefix = stack.pop()
            with os.scandir(directory) as entries:
                ordered = sorted(entries, key=lambda entry: entry.name)
            for entry in ordered:
                relative = f"{prefix}/{entry.name}" if prefix else entry.name
                canonical = _canonical_path(
                    relative.replace(os.sep, "/"), "installed output path"
                )
                path = Path(entry.path)
                if entry.is_symlink():
                    _fail(f"installed output is a symbolic link: {scheme}/{canonical}")
                if entry.is_dir(follow_symlinks=False):
                    stack.append((path, canonical))
                    continue
                if not entry.is_file(follow_symlinks=False):
                    _fail(f"installed output is not regular: {scheme}/{canonical}")
                if len(outputs) >= MAX_OUTPUT_FILES:
                    _fail("installed outputs exceed the file-count cap")
                digest, size, mode = _hash_regular(path, MAX_OUTPUT_BYTES - total)
                total += size
                outputs.append(
                    {
                        "scheme": scheme,
                        "relative_path": canonical,
                        "sha256": digest,
                        "size": size,
                        "executable": bool(
                            mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
                        ),
                    }
                )
    outputs.sort(key=lambda item: (SCHEMES.index(item["scheme"]), item["relative_path"]))
    return outputs


def _write_report(path: Path, report: dict[str, Any], output_root: Path) -> None:
    if path.exists() or path.is_symlink():
        _fail("report path already exists; exclusive creation is required")
    report_parent = path.parent.resolve(strict=True)
    output = output_root.resolve(strict=True)
    if report_parent == output or output in report_parent.parents:
        _fail("report path must remain outside the installation output root")
    encoded = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_REPORT_BYTES:
        _fail("report exceeds its byte cap")
    with path.open("xb") as stream:
        stream.write(encoded)
        stream.write(b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def _run(argv: list[str]) -> None:
    preflight_only = len(argv) == 8 and argv[7] == "--preflight-only"
    if len(argv) != 7 and not preflight_only:
        _fail(
            "usage: wheel_source.py <manifest.json> <manifest-sha256> "
            "<receipt-sha256> <installer-root> <output-root> <report.json> "
            "[--preflight-only]"
        )
    _prove_wheel_open_denied()
    manifest_path = Path(argv[1])
    manifest = _load_manifest(manifest_path, argv[2])
    members, receipt = _validate_manifest(manifest, argv[3])
    prepared = _load_member_bytes(manifest_path, members)
    install, destination_type, source_base, record_type, parse_record = _load_installer(
        Path(argv[4])
    )
    source_class = _source_type(source_base, record_type, parse_record)
    source = source_class(manifest, prepared)
    source.validate_record()
    first = _consume_source(source)
    second = _consume_source(source)
    if first != second or len(first) != len(prepared):
        _fail("WheelSource member reads are not repeatable")

    output_root = Path(argv[5]).absolute()
    scheme_dict = _prepare_destination(output_root, manifest)
    additional_metadata = {}
    if manifest["additional_installer"] is not None:
        additional_metadata["INSTALLER"] = manifest["additional_installer"].encode(
            "utf-8"
        )
    if preflight_only:
        if manifest["destination_model"] != "poetry-2.4.2-cpython-3.12-venv-v1":
            _fail("preflight-only is reserved for the Poetry destination model")
        preflight_type = _preflight_destination_type(
            destination_type,
            record_type,
            output_root,
        )
        destination = preflight_type(
            scheme_dict=scheme_dict,
            interpreter=manifest["interpreter"],
            script_kind="posix",
            hash_algorithm="sha256",
            bytecode_optimization_levels=(),
            destdir=None,
            overwrite_existing=False,
        )
        install(source, destination, additional_metadata)
        return
    writes: list[tuple[str, str, bool]] = []
    audited_destination_type = _tracking_destination_type(
        destination_type,
        writes,
        output_root,
    )
    destination = audited_destination_type(
        scheme_dict=scheme_dict,
        interpreter=manifest["interpreter"],
        script_kind="posix",
        hash_algorithm="sha256",
        bytecode_optimization_levels=(),
        destdir=None,
        overwrite_existing=False,
    )
    install(source, destination, additional_metadata)
    if manifest["destination_model"] == "fresh-separate-roots-v1":
        outputs = _enumerate_outputs(output_root)
        if outputs != _enumerate_written_outputs(destination, writes):
            _fail("complete output enumeration disagrees with installer writes")
    else:
        outputs = _enumerate_written_outputs(destination, writes)
    report = {
        "schema": REPORT_SCHEMA,
        "adapter": ADAPTER,
        "installer_version": INSTALLER_VERSION,
        "manifest_sha256": argv[2],
        "canonical_receipt_sha256": receipt,
        "wheel_open_audit": "enforced",
        "repeatable_member_reads": len(first),
        "installed_files": outputs,
    }
    _write_report(Path(argv[6]), report, output_root)


def main() -> int:
    try:
        _run(sys.argv)
    except Exception as error:
        print(f"PyPA WheelSource handoff: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
