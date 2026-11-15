# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Cirraya
"""Scripts and sources (spec v0.18, sections 5, 6, and 11): a
`kanhe.script/1` record is the organization's approval of one version of a
script, by its files' digests, given by a person in person; a statement's
provenance may name it (key 5); a registration may name the records it was
made from (key 7, its sources).

The ledger checks a script's metadata (record key 5, `script` in the CDDL)
and refuses other keys; parse() does that here. status() says where a source
stood at a time, from its history.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import NoReturn

from . import cbor
from .errors import VerifyError

SCRIPT_TYPE = "kanhe.script/1"
INITIAL = "approved"
MAX_FILES = 256
# Where a source stood at a time (section 11, step 10).
NOT_YET, LIVE, REVOKED, REPLACED = "not_yet", "live", "revoked", "replaced"

_REQUIRED = ("name", "version", "files", "deterministic")
_OPTIONAL = ("runtime",)


class ScriptError(VerifyError):
    """Metadata the ledger refuses as a script's. `why` names the rule, as
    the test vectors do."""

    def __init__(self, why: str, message: str):
        super().__init__(message)
        self.why = why


@dataclass(frozen=True)
class Script:
    name: str
    version: str
    files: tuple       # ((path, size, digest), ...), ascending by path
    deterministic: bool
    runtime: str | None


def _fail(why: str, message: str) -> NoReturn:
    raise ScriptError(why, message)


def _text(v, low: int, high: int) -> bool:
    return isinstance(v, str) and low <= len(v.encode("utf-8")) <= high


def valid_path(path) -> bool:
    """1 to 1024 bytes, relative, segments separated by "/", each non-empty
    and neither "." nor ".."."""
    if not _text(path, 1, 1024):
        return False
    return all(segment not in ("", ".", "..") for segment in path.split("/"))


def parse(metadata) -> Script:
    """A script's metadata, as deterministic CBOR bytes or as the decoded
    map, checked as the ledger checks it (section 6)."""
    if isinstance(metadata, (bytes, bytearray)):
        metadata = cbor.decode(bytes(metadata))
    if isinstance(metadata, cbor.Map):
        _fail("unknown key", "a script's metadata has a key that is not text")
    if not isinstance(metadata, dict):
        _fail("no metadata", "a script has no script metadata (record key 5)")
    if any(not isinstance(k, str) for k in metadata):
        _fail("unknown key", "a script's metadata has a key that is not text")
    unknown = set(metadata) - set(_REQUIRED) - set(_OPTIONAL)
    if unknown:
        _fail("unknown key", f"a script's metadata has an unknown key ({sorted(unknown)[0]!r})")
    missing = [k for k in _REQUIRED if k not in metadata]
    if missing:
        _fail("missing key", f"a script's metadata lacks {missing[0]!r}")
    m = metadata
    if not _text(m["name"], 1, 128):
        _fail("name", "a script's name is not a text of 1 to 128 bytes")
    if not _text(m["version"], 1, 64):
        _fail("version", "a script's version is not a text of 1 to 64 bytes")
    files = m["files"]
    if not (isinstance(files, list) and 1 <= len(files) <= MAX_FILES):
        _fail("files", "a script does not have 1 to 256 files")
    out = []
    for f in files:
        if not (isinstance(f, list) and len(f) == 3):
            _fail("file", "a script's file is not [path, size, digest]")
        path, size, digest = f
        if not valid_path(path):
            _fail("path", "a script's file path is not 1 to 1024 bytes, relative, without an empty, "
                          "\".\", or \"..\" segment")
        if not (isinstance(size, int) and not isinstance(size, bool) and size >= 0):
            _fail("size", "a script's file size is not an unsigned integer")
        if not (isinstance(digest, bytes) and len(digest) == 32):
            _fail("digest", "a script's file digest is not 32 bytes")
        if out and not out[-1][0].encode("utf-8") < path.encode("utf-8"):
            _fail("order", "a script's files do not ascend strictly by path")
        out.append((path, size, digest))
    if not isinstance(m["deterministic"], bool):
        _fail("deterministic", "a script's deterministic is not a boolean")
    if "runtime" in m and not _text(m["runtime"], 1, 128):
        _fail("runtime", "a script's runtime is not a text of 1 to 128 bytes")
    return Script(name=m["name"], version=m["version"], files=tuple(out),
                  deterministic=m["deterministic"], runtime=m.get("runtime"))


def status(registered: int, revoked: int | None, replaced: int | None, t: int) -> str:
    """Where a source stood at time t (section 11, step 10): not yet
    registered before its registration; else revoked if it was revoked at or
    before t; else replaced if a newer version was registered at or before
    t; else live."""
    if t < registered:
        return NOT_YET
    if revoked is not None and revoked <= t:
        return REVOKED
    if replaced is not None and replaced <= t:
        return REPLACED
    return LIVE
