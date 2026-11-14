"""Resolve any supported input into a local directory + build the ScanContext.

Supported inputs: local directory, single file, .zip path, git URL (https),
or a raw https URL to a file. Network fetches are guarded against SSRF: the host is
resolved once, every answer must be a public address, and the connection is pinned to
that checked address (no second DNS lookup a rebinding attacker could answer). They
never follow redirects (a redirect could hop past that guard to another host), and are
capped in size. Archives are capped in
member count, per-member bytes and total bytes before anything is written.

Completeness contract (`build_context`): every entry under the root is either scanned,
listed as a `binary` component, or recorded in `ScanContext.skipped` with the reason —
including directories that cannot be listed, symlinks that are not followed (to a
directory, outside the root, or dangling) and non-regular entries (fifo, socket,
device). Nothing is dropped silently; the engine turns any skipped entry into an
incomplete scan.
"""

from __future__ import annotations

import io
import ipaddress
import lzma
import os
import posixpath
import socket
import stat
import subprocess
import tempfile
import unicodedata
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import httpx
import yaml

from skillwarden import constants
from skillwarden.analyzers.base import ScanContext
from skillwarden.models import Component, SkippedInput, printable

# A file whose first bytes contain NUL is treated as binary (git's own heuristic).
_BINARY_SNIFF_BYTES = 8192


@dataclass
class Resolved:
    root: Path
    temp_dir: tempfile.TemporaryDirectory[str] | None  # caller closes; cleans up


class InputError(Exception):
    pass


@dataclass(frozen=True)
class _Pinned:
    """A URL's host resolved once and verified public: every connection goes to `ip`."""

    host: str
    port: int
    ip: str
    explicit_port: bool


# Address-translation prefixes: the real destination is an embedded IPv4 address that
# a local translator reaches, so "public" says nothing about where the packets go.
_TRANSLATION_NETS = (
    ipaddress.ip_network("64:ff9b::/96"),  # NAT64 well-known prefix (RFC 6052)
    ipaddress.ip_network("64:ff9b:1::/48"),  # NAT64 local-use prefix (RFC 8215)
    ipaddress.ip_network("2002::/16"),  # 6to4
    ipaddress.ip_network("2001::/32"),  # Teredo
)


def _host_of(url: str) -> str:
    """The URL's host, lower-cased and without the DNS root dot (`github.com.`)."""
    return (urlparse(url).hostname or "").lower().rstrip(".")


def _pin_public_address(url: str) -> _Pinned:
    """Resolve the URL's host ONCE and refuse unless every answer is a public address.

    The returned address is the one the fetch or clone connects to (DNS rebinding
    guard): nothing re-resolves the name between this check and the connection.
    """
    parsed = urlparse(url)
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        raise InputError("URLs with embedded credentials (user@host) are unsupported.")
    host = _host_of(url)
    if not host:
        raise InputError(f"URL has no host: {url!r}")
    try:
        port = parsed.port or 443
    except ValueError as exc:
        raise InputError(f"Invalid port in URL {url!r}: {exc}") from exc
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as exc:
        raise InputError(f"Cannot resolve host {host!r}: {exc}") from exc
    addresses: list[str] = []
    for info in infos:
        ip = ipaddress.ip_address(str(info[4][0]).split("%", 1)[0])
        mapped = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) else None
        effective = mapped or ip
        translated = any(effective in net for net in _TRANSLATION_NETS)
        if not effective.is_global or effective.is_multicast or translated:
            raise InputError(f"Refusing to fetch non-public address {ip} (SSRF guard).")
        addresses.append(str(effective))
    if not addresses:
        raise InputError(f"Cannot resolve host {host!r}: no addresses")
    return _Pinned(host=host, port=port, ip=addresses[0], explicit_port=parsed.port is not None)


# Known git hosts: an exact host match plus a repository-shaped path is cloned. Any other
# host is cloned only when the path ends in `.git`; everything else is a file fetch.
_GITHUB_HOSTS = {"github.com", "www.github.com"}
_GITLAB_HOSTS = {"gitlab.com", "www.gitlab.com"}


def _is_git_repository(url: str) -> bool:
    """Route by exact host and path shape (never a substring of the URL).

    Raises InputError for a non-repository path on a known git host (a blob/tree page
    is HTML, not the skill): pass the repository URL or a raw file URL instead.
    """
    parsed = urlparse(url)
    host = _host_of(url)
    segments = [s for s in parsed.path.split("/") if s]
    if host in _GITHUB_HOSTS or host in _GITLAB_HOSTS:
        repo_shaped = (
            len(segments) == 2 if host in _GITHUB_HOSTS else len(segments) >= 2
        ) and "-" not in segments
        if not repo_shaped or parsed.query or parsed.fragment:
            raise InputError(
                f"Unsupported {host} URL {url!r}: pass a repository URL "
                "(https://github.com/<owner>/<repo>) or a raw file URL."
            )
        return True
    return parsed.path.endswith(".git")


def resolve(input_path: str) -> Resolved:
    """Turn user input into a local root directory."""
    p = Path(input_path).expanduser()

    if p.is_dir():
        return Resolved(root=p, temp_dir=None)
    if p.is_file():
        if is_zip_path(p):
            size = p.stat().st_size
            if size > constants.MAX_TOTAL_BYTES:
                raise InputError(
                    f"Refusing zip archive of {size} bytes: exceeds the total input limit "
                    f"({constants.MAX_TOTAL_BYTES} bytes)."
                )
            return _extract_zip(p.read_bytes())
        return Resolved(
            root=p.parent, temp_dir=None
        )  # single-file: scan its dir? no — scan the file
    if input_path.startswith("http://"):
        raise InputError("Plain http:// inputs are unsupported; use https://.")
    if input_path.startswith("https://"):
        # Each path resolves the host once, verifies it and connects to that address.
        if _is_git_repository(input_path):
            return _clone_git(input_path)
        return _fetch_url(input_path)

    raise InputError(f"Unsupported input: {input_path!r}")


def is_zip_path(p: Path) -> bool:
    """A `.zip` input, whatever the suffix's case (`.ZIP` is extracted, not listed)."""
    return p.suffix.lower() == ".zip"


def _check_ratio(what: str, uncompressed: int, compressed: int) -> None:
    """Refuse a zip-bomb shape: uncompressed size far beyond what was compressed."""
    if uncompressed <= constants.ZIP_RATIO_FLOOR_BYTES:
        return
    if uncompressed > constants.MAX_ZIP_RATIO * max(compressed, 1):
        raise InputError(
            f"Refusing zip: {what} expands {compressed} bytes to {uncompressed} bytes, over "
            f"the maximum compression ratio of {constants.MAX_ZIP_RATIO}:1 (zip-bomb guard)."
        )


# Compression methods Python's zipfile can decompress: stored, deflate, bzip2, lzma.
_ZIP_METHODS = {
    zipfile.ZIP_STORED,
    zipfile.ZIP_DEFLATED,
    zipfile.ZIP_BZIP2,
    zipfile.ZIP_LZMA,
}
# What a failing decompressor (or a CRC check) can raise while a member is read.
_ZIP_READ_ERRORS = (
    zipfile.BadZipFile,
    RuntimeError,
    NotImplementedError,
    zlib.error,
    EOFError,
    lzma.LZMAError,
)


# PATH_MAX on Linux. Longer names cannot be extracted anywhere, and refusing them first
# keeps every later per-name step (normalise, parent walk, resolve) cheap.
_MAX_MEMBER_NAME_BYTES = 4096


def _member_key(name: str) -> str:
    """The destination a member would get from ANY unpacker, for collision checks.

    Unicode-normalised (NFC), backslashes as separators, `.`/`..`/`//` collapsed, and
    case-folded (case-insensitive filesystems collide on `SKILL.md` / `skill.md`).
    """
    unified = unicodedata.normalize("NFC", name).replace("\\", "/")
    return posixpath.normpath(unified).casefold()


def _validate_members(zf: zipfile.ZipFile) -> None:
    """Refuse, before anything is written, an archive whose members cannot all be
    extracted to distinct regular files exactly as listed (otherwise one copy would
    silently overwrite another and never be scanned)."""
    files: dict[str, str] = {}
    dirs: dict[str, str] = {}
    for info in zf.infolist():
        name = info.filename
        if len(name.encode("utf-8", "surrogateescape")) > _MAX_MEMBER_NAME_BYTES:
            raise InputError(
                f"Refusing zip: member name {name[:60]!r}… is too long "
                f"(over {_MAX_MEMBER_NAME_BYTES} bytes; no filesystem can extract it)."
            )
        if not name.strip("/"):
            raise InputError("Refusing zip: a member has an empty name.")
        if info.flag_bits & 0x1:
            raise InputError(f"Refusing zip: member {name!r} is encrypted.")
        if info.compress_type not in _ZIP_METHODS:
            raise InputError(
                f"Refusing zip: member {name!r} uses unsupported compression method "
                f"{info.compress_type}."
            )
        if stat.S_ISLNK(info.external_attr >> 16):
            raise InputError(f"Refusing zip: member {name!r} is a symlink (unsupported).")
        key = _member_key(name)
        if key == "." and info.is_dir():
            continue  # an explicit "./" entry for the root itself
        if key in (".", "..") or key.startswith(("../", "/")):
            raise InputError(f"Zip entry escapes extraction root: {name!r}")
        if info.is_dir():
            dirs.setdefault(key, name)
            continue
        if key in files:
            raise InputError(
                f"Refusing zip: members {files[key]!r} and {name!r} have the same "
                "destination; one would overwrite the other unscanned."
            )
        files[key] = name
        parent = posixpath.dirname(key)
        while parent and parent not in dirs:  # known parent => its ancestors are too
            dirs[parent] = name
            parent = posixpath.dirname(parent)
    for key, name in files.items():
        if key in dirs:
            raise InputError(
                f"Refusing zip: {name!r} is both a file and a directory "
                f"(see {dirs[key]!r}); member names collide."
            )


def _extract_zip(data: bytes) -> Resolved:
    """Extract an in-memory zip under the scanning limits.

    Refuses (before writing anything) archives with more members than MAX_COMPONENTS,
    any member over MAX_FILE_BYTES, a declared total over MAX_TOTAL_BYTES, or a member or
    whole archive whose compression ratio exceeds MAX_ZIP_RATIO (zip-bomb guard).
    Extraction is streamed and re-counted so a lying header cannot exceed the caps either.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise InputError(f"Not a valid zip archive: {exc}") from exc
    with zf:
        members = [m for m in zf.infolist() if not m.is_dir()]
        if len(members) > constants.MAX_COMPONENTS:
            raise InputError(
                f"Refusing zip with {len(members)} members: exceeds the component limit "
                f"({constants.MAX_COMPONENTS})."
            )
        declared_total = 0
        for m in members:
            if m.file_size > constants.MAX_FILE_BYTES:
                raise InputError(
                    f"Refusing zip member {m.filename!r} of {m.file_size} bytes: exceeds the "
                    f"per-file limit ({constants.MAX_FILE_BYTES} bytes)."
                )
            _check_ratio(f"member {m.filename!r}", m.file_size, m.compress_size)
            declared_total += m.file_size
        if declared_total > constants.MAX_TOTAL_BYTES:
            raise InputError(
                f"Refusing zip: declared total of {declared_total} bytes exceeds the "
                f"total input limit ({constants.MAX_TOTAL_BYTES} bytes)."
            )
        _check_ratio("the archive", declared_total, len(data))
        _validate_members(zf)

        td = tempfile.TemporaryDirectory(prefix="skillwarden-")
        root = Path(td.name).resolve()
        try:
            for member in zf.infolist():
                # Zip-slip guard: reject paths that escape the extraction root.
                dest = (root / member.filename).resolve()
                if not dest.is_relative_to(root):
                    raise InputError(f"Zip entry escapes extraction root: {member.filename!r}")
            written_total = 0
            for member in members:
                dest = (root / member.filename).resolve()
                written = 0
                try:
                    # Colliding names ('a' then 'a/b.py', or the reverse) make these fail;
                    # that is a malformed archive, not a crash.
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as src, dest.open("wb") as fh:
                        while chunk := src.read(65536):
                            written += len(chunk)
                            written_total += len(chunk)
                            if written > constants.MAX_FILE_BYTES:
                                raise InputError(
                                    f"Refusing zip member {member.filename!r}: exceeds the "
                                    f"per-file limit ({constants.MAX_FILE_BYTES} bytes)."
                                )
                            if written_total > constants.MAX_TOTAL_BYTES:
                                raise InputError(
                                    "Refusing zip: extracted total exceeds the total input "
                                    f"limit ({constants.MAX_TOTAL_BYTES} bytes)."
                                )
                            fh.write(chunk)
                except OSError as exc:  # filesystem errors, and bz2's corrupt-stream error
                    raise InputError(
                        f"Refusing zip: cannot extract member {member.filename!r} "
                        f"({_oserror(exc)}); the member is malformed or its name collides."
                    ) from exc
        except _ZIP_READ_ERRORS as exc:
            td.cleanup()
            raise InputError(
                f"Refusing zip: a member cannot be decompressed ({type(exc).__name__}: {exc})."
            ) from exc
        except BaseException:
            td.cleanup()
            raise
    return Resolved(root=root, temp_dir=td)


# `http.curloptResolve` (curl's CURLOPT_RESOLVE) arrived in git 2.37. Older git ignores
# the unknown key silently, so the clone would re-resolve the host: refuse instead.
_MIN_GIT_FOR_PINNING = (2, 37)


def _git_env() -> dict[str, str]:
    """A minimal git environment: no prompts, no proxy variables, and no system or
    global config (which could rewrite the URL via `insteadOf` or add a proxy)."""
    return {
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "PATH": "/usr/bin:/bin",
    }


def _git_clone_command(url: str, host: str, port: int, ip: str, dest: str) -> list[str]:
    pinned_ip = f"[{ip}]" if ":" in ip else ip
    return [
        "git",
        # Redirects are unsupported by design: a redirecting remote could send the
        # clone to a host the SSRF guard never checked.
        "-c",
        "http.followRedirects=false",
        # Connect to the address that was checked, not a fresh DNS answer.
        "-c",
        f"http.curloptResolve={host}:{port}:{pinned_ip}",
        "clone",
        "--depth",
        "1",
        "--quiet",
        url,
        dest,
    ]


def _check_git_can_pin() -> None:
    try:
        out = subprocess.run(
            ["git", "--version"],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
            env=_git_env(),
        ).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        raise InputError(f"git is unavailable: {exc}") from exc
    parts = out.split()
    try:
        version = tuple(int(x) for x in parts[2].split(".")[:2])
    except (IndexError, ValueError) as exc:
        raise InputError(f"Cannot parse git version from {out.strip()!r}") from exc
    if version < _MIN_GIT_FOR_PINNING:
        raise InputError(
            f"git {parts[2]} cannot pin the checked address (needs git >= 2.37 for "
            "http.curloptResolve); refusing to clone. Download the skill and scan it locally."
        )


def _clone_git(url: str) -> Resolved:
    if not url.startswith("https://"):
        raise InputError("git clone inputs must be https:// URLs.")
    pinned = _pin_public_address(url)
    _check_git_can_pin()
    td = tempfile.TemporaryDirectory(prefix="skillwarden-")
    try:
        subprocess.run(
            _git_clone_command(url, pinned.host, pinned.port, pinned.ip, td.name),
            check=True,
            capture_output=True,
            timeout=120,
            env=_git_env(),
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        td.cleanup()
        raise InputError(f"git clone failed: {exc}") from exc
    return Resolved(root=Path(td.name), temp_dir=td)


def _fetch_url(url: str, transport: httpx.BaseTransport | None = None) -> Resolved:
    pinned = _pin_public_address(url)
    # Connect to the checked IP; the original name goes in the Host header and in TLS
    # SNI, so the certificate is still verified against the hostname.
    host_header = f"{pinned.host}:{pinned.port}" if pinned.explicit_port else pinned.host
    target = httpx.URL(url).copy_with(host=pinned.ip, username=None, password=None)
    td = tempfile.TemporaryDirectory(prefix="skillwarden-")
    root = Path(td.name)
    name = Path(urlparse(url).path).name or "downloaded"
    try:
        with (
            httpx.Client(
                timeout=constants.NETWORK_TIMEOUT,
                follow_redirects=False,
                transport=transport,
                trust_env=False,  # no proxy: a proxy would resolve the name itself
            ) as client,
            client.stream(
                "GET",
                target,
                headers={"Host": host_header},
                extensions={"sni_hostname": pinned.host},
            ) as r,
        ):
            if r.is_redirect or 300 <= r.status_code < 400:
                raise InputError(
                    f"Refusing HTTP redirect ({r.status_code}) from {url}: redirects are "
                    "unsupported; pass the final URL directly."
                )
            r.raise_for_status()
            total = 0
            dest = root / name
            with dest.open("wb") as fh:
                for chunk in r.iter_bytes():
                    total += len(chunk)
                    if total > constants.MAX_FILE_BYTES:
                        raise InputError("Remote file exceeds size limit.")
                    fh.write(chunk)
    except httpx.HTTPError as exc:
        td.cleanup()
        raise InputError(f"Fetch failed: {exc}") from exc
    except BaseException:
        td.cleanup()
        raise
    return Resolved(root=root, temp_dir=td)


# --- context construction -------------------------------------------------


def build_context(target: str, root: Path, single_file: Path | None = None) -> ScanContext:
    """Walk the resolved root, read text components, parse the manifest.

    Every entry is accounted for: scanned (strictly or lossily decoded), listed as a
    `binary` component, or recorded in `skipped` with the reason (see `_walk`). `.git`
    internals are excluded from the walk by design (they are not part of the skill).
    """
    paths: list[Path]
    skipped: list[SkippedInput] = []
    if single_file is not None:
        base = single_file.parent
        try:
            single_file.name.encode("utf-8")
            paths = [single_file]
        except UnicodeEncodeError:
            # Same rule as the walk: a name the report cannot represent is recorded
            # under a backslash-escaped spelling (scan incomplete), never scanned.
            shown = os.fsencode(single_file.name).decode("utf-8", errors="backslashreplace")
            skipped.append(SkippedInput(path=shown, reason="name is not valid UTF-8; not scanned"))
            paths = []
    else:
        paths, skipped = _walk(root)
        base = root

    components: list[Component] = []
    file_cache: dict[str, str] = {}
    warnings: list[str] = []
    total = 0

    for index, p in enumerate(sorted(paths)):
        rel = str(p.relative_to(base))
        if index >= constants.MAX_COMPONENTS:
            skipped.append(
                SkippedInput(
                    path=rel,
                    reason=f"component limit ({constants.MAX_COMPONENTS} files) exceeded",
                )
            )
            continue
        try:
            size = p.stat().st_size
        except OSError as exc:
            skipped.append(SkippedInput(path=rel, reason=f"unreadable: {_oserror(exc)}"))
            continue
        if size > constants.MAX_FILE_BYTES:
            skipped.append(
                SkippedInput(
                    path=rel,
                    reason=f"{size} bytes exceeds the per-file limit "
                    f"({constants.MAX_FILE_BYTES} bytes)",
                )
            )
            continue
        if total + size > constants.MAX_TOTAL_BYTES:
            skipped.append(
                SkippedInput(
                    path=rel,
                    reason=f"total input limit ({constants.MAX_TOTAL_BYTES} bytes) exceeded",
                )
            )
            continue
        total += size

        suffix = p.suffix.lower()
        ftype = constants.TYPE_BY_EXTENSION.get(suffix, "other")
        executable = suffix in constants.EXECUTABLE_EXTENSIONS
        try:
            data = p.read_bytes()
        except OSError as exc:
            skipped.append(SkippedInput(path=rel, reason=f"unreadable: {_oserror(exc)}"))
            continue

        kind = _archive_kind(data)
        if kind is not None:
            # Its contents are part of the skill but were never examined.
            skipped.append(
                SkippedInput(
                    path=rel,
                    reason=f"nested archive ({kind}) not scanned; unpack it and scan the contents",
                )
            )
            continue

        text = ""
        lossy = False
        try:
            text = data.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            if b"\x00" in data[:_BINARY_SNIFF_BYTES]:
                if ftype == "other":
                    ftype = "binary"  # a real binary: listed, not text-scanned (by design)
                else:
                    skipped.append(
                        SkippedInput(
                            path=rel,
                            reason=f"declared {ftype} file contains NUL bytes and is not "
                            "valid UTF-8; not scanned",
                        )
                    )
                    continue
            else:
                # Text with stray bytes: scan it lossily and say so, rather than hide it.
                text = data.decode("utf-8", errors="replace")
                lossy = True
                warnings.append(
                    f"{rel}: not valid UTF-8 (first invalid byte at offset {exc.start}); "
                    "decoded with replacement characters and scanned lossily"
                )
        if ftype != "binary":
            file_cache[rel] = text
        components.append(
            Component(
                path=rel,
                type=ftype,
                lines=text.count("\n") + 1 if text else 0,
                size_bytes=size,
                executable=executable,
                lossy_decode=lossy,
            )
        )

    manifest = _parse_manifest(file_cache)
    return ScanContext(
        target=printable(target),
        components=components,
        file_cache=file_cache,
        manifest=manifest,
        skipped=skipped,
        warnings=warnings,
    )


# Magic numbers of archive / compressed formats whose contents a text scan cannot see.
_ARCHIVE_MAGIC = (
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"PK\x07\x08", "zip"),
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"7z\xbc\xaf\x27\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
)


def _archive_kind(data: bytes) -> str | None:
    for magic, kind in _ARCHIVE_MAGIC:
        if data.startswith(magic):
            if kind == "bzip2" and not (
                len(data) >= 10 and data[3] in b"123456789" and data[4:10] == b"1AY&SY"
            ):
                continue  # prose starting "BZh9 ...", not "BZh<level>" + block magic
            return kind
    if data[257:263] == b"ustar\x00" or data[257:265] == b"ustar  \x00":
        return "tar"  # POSIX ustar, or old GNU tar
    if zipfile.is_zipfile(io.BytesIO(data)):
        return "zip"  # a zip behind leading junk: zipfile and unzip still open it
    return None


def _oserror(exc: OSError) -> str:
    return exc.strerror or str(exc)


def _walk(root: Path) -> tuple[list[Path], list[SkippedInput]]:
    """Explicit, non-following walk of ``root``: regular files to scan + skipped entries.

    `pathlib.rglob` is not used because it swallows PermissionError on unlistable
    directories and silently ignores dangling / directory symlinks and non-regular
    entries. Here every such entry is recorded:

    * a directory that cannot be listed (root included, as ".") -> unreadable directory
    * a symlink to a directory -> not followed (descending outside the root is unsafe;
      inside the root it would double-scan or loop), recorded
    * a symlink to a regular file: followed and scanned only when the target resolves
      inside the root; otherwise recorded
    * a dangling symlink, or a fifo / socket / device -> recorded, never opened
    * anything named `.git` is excluded by design (not part of the skill)
    """
    files: list[Path] = []
    skipped: list[SkippedInput] = []
    real_root = os.path.realpath(root)

    def rel(path: str) -> str:
        return os.path.relpath(path, root) if path != str(root) else "."

    def safe_name(path: str) -> str | None:
        """The relative name, or None (recorded) when it is not valid UTF-8.

        Such a name cannot be represented in the JSON/SARIF report, so the entry
        is recorded under a backslash-escaped spelling and never scanned.
        """
        name = rel(path)
        try:
            name.encode("utf-8")
        except UnicodeEncodeError:
            shown = os.fsencode(name).decode("utf-8", errors="backslashreplace")
            skipped.append(SkippedInput(path=shown, reason="name is not valid UTF-8; not scanned"))
            return None
        return name

    # Explicit stack of directory listings (not recursion): a hostile tree deeper
    # than the interpreter's recursion limit must still end in a complete or
    # honestly incomplete report. Entries are visited in pre-order, exactly as
    # the recursive walk did: a directory's contents before its later siblings.
    def listing(directory: str) -> Iterator[os.DirEntry[str]] | None:
        try:
            with os.scandir(directory) as it:
                return iter(sorted(it, key=lambda e: e.name))
        except OSError as exc:
            skipped.append(
                SkippedInput(path=rel(directory), reason=f"unreadable directory: {_oserror(exc)}")
            )
            return None

    stack: list[Iterator[os.DirEntry[str]]] = []
    first = listing(str(root))
    if first is not None:
        stack.append(first)
    while stack:
        entry = next(stack[-1], None)
        if entry is None:
            stack.pop()
            continue
        if entry.name == ".git":
            continue
        path = entry.path
        name = safe_name(path)
        if name is None:
            continue
        try:
            mode = entry.stat(follow_symlinks=False).st_mode
        except OSError as exc:
            skipped.append(SkippedInput(path=name, reason=f"unreadable: {_oserror(exc)}"))
            continue
        if stat.S_ISLNK(mode):
            _classify_symlink(path, name, real_root, files, skipped)
        elif stat.S_ISDIR(mode):
            sub = listing(path)
            if sub is not None:
                stack.append(sub)
        elif stat.S_ISREG(mode):
            files.append(Path(path))
        else:
            skipped.append(SkippedInput(path=name, reason=f"not a regular file ({_kind(mode)})"))

    return files, skipped


def _classify_symlink(
    path: str, rel: str, real_root: str, files: list[Path], skipped: list[SkippedInput]
) -> None:
    try:
        target = os.readlink(path)
    except OSError:
        target = "?"
    try:
        mode = os.stat(path).st_mode  # follows the link
    except OSError as exc:
        skipped.append(
            SkippedInput(path=rel, reason=f"dangling symlink -> {target!r} ({_oserror(exc)})")
        )
        return
    if stat.S_ISDIR(mode):
        skipped.append(
            SkippedInput(path=rel, reason=f"symlink to a directory -> {target!r}; not followed")
        )
        return
    if not stat.S_ISREG(mode):
        skipped.append(
            SkippedInput(
                path=rel, reason=f"symlink to a non-regular file ({_kind(mode)}) -> {target!r}"
            )
        )
        return
    real = os.path.realpath(path)
    if os.path.commonpath([real_root, real]) != real_root:
        skipped.append(
            SkippedInput(
                path=rel,
                reason=f"symlink to a file outside the skill root -> {target!r}; not followed",
            )
        )
        return
    files.append(Path(path))


def _kind(mode: int) -> str:
    if stat.S_ISFIFO(mode):
        return "fifo"
    if stat.S_ISSOCK(mode):
        return "socket"
    if stat.S_ISCHR(mode):
        return "character device"
    if stat.S_ISBLK(mode):
        return "block device"
    return "unknown type"


def _parse_manifest(file_cache: dict[str, str]) -> dict[str, object]:
    """Pull YAML frontmatter out of SKILL.md if present."""
    for key in ("SKILL.md", "skill.md"):
        text = file_cache.get(key)
        if text and text.startswith("---"):
            parts = text.split("---", 2)
            if len(parts) >= 3:
                try:
                    data = yaml.safe_load(parts[1])
                    return data if isinstance(data, dict) else {}
                except yaml.YAMLError:
                    return {}
    return {}
