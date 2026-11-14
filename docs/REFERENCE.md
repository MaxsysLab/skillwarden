# SkillWarden reference

The exact behaviour behind the summary in the [README](../README.md): exit codes, what
makes a scan incomplete, what is refused, how hostile text is kept out of reports, and
how the AI pass is held in check.

## Scan status and exit codes

A scan is **`complete`** only when every requested part ran over every input file.
Anything less is **`incomplete`**: the report still shows whatever static findings
were produced, but the recommendation says the result is not a clearance, and the
process exits **2** regardless of `--fail-on`. Never treat an incomplete scan as a pass.

| Exit | Meaning |
|------|---------|
| `0` | scan complete, label below `--fail-on` |
| `1` | scan complete, label at or above `--fail-on` |
| `2` | scan **incomplete** (see below), the input could not be resolved, or a usage error: an unknown `--format` (terminal, json, markdown, sarif) or `--fail-on` (none, info, low, medium, high, critical) value is refused with one `Error:` line before any scan runs, never replaced by a default |

A scan is incomplete when any of these happened (each is listed under `errors`, and
dropped files also under `skipped`, in every output format: JSON, SARIF
`runs[0].properties.status/skipped` + `executionSuccessful: false`, Markdown, terminal):

- **The AI pass was requested (the default) but did not fully run.** No provider is
  available, the provider errors, the primary reply or the refuter reply is malformed, a
  refutation lacks per-finding evidence, or the skill is larger than the total review
  budget (`SKILLWARDEN_LLM_MAX_CHARS`, 3,000,000 characters), so some of its text was
  shown to the model in no call (each prompt names the files left out).
  Static findings are kept untouched; no downgrade is ever applied from a failed pass.
  Use `--no-llm` for a static-only scan that can be complete without a provider.
- **The known-vulnerability lookup was needed and did not run.** The skill pins
  dependencies (`requirements.txt`, `package.json`) and osv.dev could not be reached, or
  its answer could not be read. Use `--no-osv` to scan without the lookup; the report
  then carries a warning that names how many dependencies were not checked.
- **Input was dropped by a limit or was unreadable.** Files beyond
  `SKILLWARDEN_MAX_COMPONENTS` (2000), over `SKILLWARDEN_MAX_FILE_BYTES` (2 MiB), past
  `SKILLWARDEN_MAX_TOTAL_BYTES` (50 MiB), unreadable (permissions, I/O), or a file with a
  code/markup extension that contains NUL bytes. Each is recorded with its reason.
- **A directory could not be listed** (permissions, I/O), including the skill root
  itself, recorded as `.`. The files inside it were never seen, so the scan cannot be
  complete. The walk is explicit (no `rglob`), so this is never swallowed.
- **An entry was not a regular file.** A symlink to a directory is never followed
  (descending outside the root is unsafe; inside the root it would double-scan or loop);
  a dangling symlink, a fifo, a socket or a device is never opened. Each is recorded
  with its reason. A symlink to a *file* is followed and scanned only when its target
  resolves inside the skill root (it is part of the skill); a symlink to a file outside
  the root is recorded as skipped, not scanned.
- **An entry's name is not valid UTF-8.** It cannot be represented in the report, so it
  is recorded (backslash-escaped) and never scanned or descended into. The walk uses an
  explicit stack, so a tree deeper than the interpreter's recursion limit still ends in
  a complete or honestly incomplete report; an entry whose path exceeds the OS limit is
  recorded as unreadable (`File name too long`).
- **There was nothing to scan.** An empty directory (or one whose only entries are
  `.git` internals) is never reported as a clean pass. A single-file target whose name
  is not valid UTF-8 is recorded as skipped, like the same name inside a directory.
- **An analyzer failed**, or no analyzers are registered.

Not incomplete, but marked: a text file that is not valid UTF-8 (stray bytes, no NUL) is
decoded with replacement characters and scanned; the component carries
`lossy_decode: true` and a warning names the file and byte offset. Files with an unknown
extension that contain NUL bytes are listed as `binary` components and not text-scanned
(by design: SkillWarden is a text scanner). `.git/` internals are never walked.

An **archive nested inside the skill** (zip, gzip, bzip2, xz, 7z, rar, zstd or tar,
detected by its magic bytes whatever its name (the full header, e.g. `ustar\0` /
`ustar  \0` for tar and `BZh<1-9>1AY&SY` for bzip2, so prose cannot trip it), and any
file `zipfile` can open, including a zip behind leading junk bytes) is not unpacked: it is recorded under
`skipped` as `nested archive (<kind>) not scanned`, so the scan is **incomplete** (exit
2). Unpack it and scan the contents.

## Untrusted text in reports

File names, finding text, LLM output and error messages are treated as hostile in every
format. The terminal report never interprets Rich markup from them (`[red]`, `[/x]` are
shown literally), and control characters (ESC and other C0/C1 bytes), bidi overrides
and line separators are shown as visible escapes such as `\x1b` or `\u202e`, so they
cannot restyle the terminal or forge a report line. Markdown gets the same escaping plus
escaped table pipes and code spans their own backticks cannot close. JSON and SARIF stay
valid and exact; any raw C1/bidi character is written as a `\uXXXX` escape. `--format
json|sarif` on stdout is printed verbatim (not re-rendered).

## Unsupported by design (refused with a clear error, or reported incomplete)

- **Skills that bundle zip-container files** (`.docx`, `.xlsx`, `.pptx`, `.jar`, or any
  other file `zipfile` can open). Their contents are never unpacked, so such a skill can
  never get a complete scan: it is reported **incomplete** (exit 2) with the file under
  `skipped` as a nested archive.
- **Redirects.** `https://` file fetches do not follow HTTP redirects (a 3xx is refused:
  pass the final URL), and git clones run with `http.followRedirects=false`. A redirect
  could hop past the SSRF guard to a host that was never checked.
- **Plain `http://` inputs**: use `https://`. **URLs with credentials** (`user@host`)
  are refused too.
- **Non-public or re-resolved addresses (SSRF / DNS rebinding).** The host is resolved
  once; every answer must be a public (globally routable, non-multicast) address,
  IPv4-mapped IPv6 included; address-translation prefixes (NAT64 `64:ff9b::/96` and
  `64:ff9b:1::/48`, 6to4 `2002::/16`, Teredo `2001::/32`) are refused because the real
  destination is an embedded IPv4 address. The connection is then pinned to that checked address:
  file fetches connect to the IP with the original `Host` header and TLS SNI (the
  certificate is still verified against the hostname) and ignore proxy variables; git
  clones pass `-c http.curloptResolve=host:port:ip` with system/global git config
  disabled. Git older than 2.37 cannot pin, so cloning is refused rather than run
  unpinned.
- **URL routing is by exact host and path shape.** `https://github.com/<owner>/<repo>`
  (also `www.github.com`, optional `.git`/trailing `/`) and
  `https://gitlab.com/<group>/…/<repo>` are cloned; any other host is cloned only when
  the path ends in `.git`, otherwise the URL is fetched as one file. Host matching is
  case-insensitive and ignores the DNS root dot (`https://github.com./o/r` is GitHub). Look-alikes such as
  `https://github.com.evil.example/…` or `https://evil.example/github.com/x.zip` are
  never cloned as GitHub. Other GitHub/GitLab paths (`/blob/…`, `/tree/…`, `/-/…`, a
  bare owner) are refused: pass the repository URL or a raw file URL.
- **Archives over the limits.** A `.zip` is refused before extraction when the file
  itself exceeds `MAX_TOTAL_BYTES`, when it has more members than `MAX_COMPONENTS`, when
  any member exceeds `MAX_FILE_BYTES`, or when the declared total exceeds
  `MAX_TOTAL_BYTES`; extraction is streamed and re-counted so a lying header cannot
  exceed the caps either. Corrupt archives and zip-slip paths are refused.
- **Zip bombs.** Before anything is extracted, a member or the whole archive whose
  uncompressed size exceeds `SKILLWARDEN_MAX_ZIP_RATIO` (default 100) times its
  compressed size is refused, once that uncompressed size passes
  `SKILLWARDEN_ZIP_RATIO_FLOOR_BYTES` (1 MiB; small repetitive files are normal). The
  `.zip` suffix is matched case-insensitively (`skill.ZIP` is unpacked and scanned, not
  listed as one opaque binary). Every archive refusal is an input error: exit 2.
- **Ambiguous or unreadable zip members**, refused before extraction: two members with
  the same destination after normalisation (`SKILL.md` / `./SKILL.md`, `a//x.sh`,
  `a\x.sh`, `..` segments, Unicode NFC forms, or names differing only in case, which
  collide on case-insensitive filesystems); a name that is both a file and a directory;
  symlink members; member names over 4096 bytes (no filesystem can extract them, and
  refusing them first keeps the checks linear); encrypted members; compression methods other than stored, deflate,
  bzip2 and lzma. A stream that fails to decompress or fails its CRC check is refused
  the same way (exit 2), never a traceback.
- **An unusable `--baseline`** (missing, unreadable, not YAML, not a mapping, or
  `fingerprints`/`rule_globs` not a list of strings) is refused with an error on stderr
  and exit 2; no scan runs, so it is never mistaken for exit 1 ("findings").

## The AI pass and its backends

The provider is swappable via `SKILLWARDEN_PROVIDER` (default `auto`):

| Value | Backend | Auth | For |
|-------|---------|------|-----|
| `auto` *(default)* | API key, then Claude CLI, then Ollama | | whatever the machine has |
| `claude_cli` | installed `claude` CLI (`claude -p`) | your Claude Code sign-in | a machine where Claude Code is signed in: no key to provision |
| `anthropic` | `anthropic` Python SDK | `ANTHROPIC_API_KEY` | servers and CI, where a key is the normal way |
| `ollama` | local Ollama server | none (local) | offline and air-gapped scanning |

With `auto`, an API key is used if one is set; otherwise the Claude Code CLI if it is
installed; otherwise a local Ollama server if one answers. Tune with
`SKILLWARDEN_MODEL` (the API model), `SKILLWARDEN_CLI_MODEL` (`opus`),
`SKILLWARDEN_OLLAMA_MODEL` (`llama3.1`), `SKILLWARDEN_OLLAMA_URL` and
`SKILLWARDEN_OLLAMA_NUM_CTX` (`8192`). When no backend is available the requested pass
did not run and the scan is reported **incomplete** (exit 2); `--no-llm` skips it
explicitly and the static scan can then be complete.

**The model is given nothing to act with.** The text of the skill under review may be
hostile. Through the Claude Code CLI the model runs with no tools, no MCP servers and
none of the machine's settings, in a throwaway folder; the skill text travels on stdin.
A CLI too old to accept those options exits with an error, and the scan is incomplete.

**Every character is shown to the model.** A skill that fits in one call
(`SKILLWARDEN_LLM_BATCH_CHARS`, 200,000 characters by default, or less for a backend
with a small context window) is reviewed whole. A larger one is reviewed in parts, one
call each, until all of it has been shown. A file too long for one call is cut at line
ends and each piece is labelled with its place in the file.

**A skill reviewed in parts can gain findings but never has one lowered.** What makes a
line dangerous may sit in a part the reviewer was not shown, so a false-positive call
needs the whole skill in one view.

**Ollama.** Ollama shortens a prompt that is longer than the model's context window
without reporting it. SkillWarden sets the window on every call and sizes each prompt
to fit inside it. It has no tokenizer, so it uses the one bound that cannot be wrong: a
token is at least one byte, so a prompt whose size in bytes is within the window fits.
A prompt that could exceed the window is refused before it is sent. The default window
(8,192 tokens) leaves room for only about 4,000 characters of a skill per call, so
most skills are then reviewed in several parts and no finding is lowered. Raise
`SKILLWARDEN_OLLAMA_NUM_CTX` to what your model allows.

**A backend too small for the prompt.** If a backend names a limit so small that the
system text and the list of findings leave almost no room for the skill, the pass does
not run and the scan is incomplete. The refuting call is skipped, and nothing is
lowered, when its own prompt would not fit.

**Hostile names and contents.** In file headers, a file name is written with newlines,
backticks and control characters escaped, and each file sits in a code fence longer
than any run of backticks inside it, so its content cannot close the fence and pass
for part of the prompt. In the list of findings, a file name is written as it is: the
model has to name the file back, and its answer is matched on the exact name. A name
that contains a newline can therefore add lines to that list. It cannot lower a finding
by itself, because lowering needs the second call to name one listed finding exactly
and quote its evidence.

**Sizes are counted the way the backend counts them.** Ollama's limit is in bytes, so
prompts for it are planned in bytes; a skill written in a non-Latin script is sized
correctly. The longer code fence around text with long runs of backticks is not
counted, so on a small window such a skill can make the pass fail (the scan is then
incomplete).

The semantic pass may only *lower the confidence* of a static finding after a second,
adversarial model call confirms the false-positive claim **per finding, with evidence**:
each confirmation names the exact `rule_id`/`file`/`line` and a non-empty rationale,
which is attached to the finding's description. Entries without evidence, or that do
not match a listed finding, are malformed and fail the pass (scan incomplete). Static
findings are never dropped.

## Scoring

Each finding carries a severity and a confidence. The score combines them as
independent pieces of evidence (a noisy-OR), so it climbs toward 100 as evidence
gathers but never by simple addition. Repeats of one rule count at most three times.
A skill that ships executable scripts has its score raised by a quarter.

| Score | Label | What the report recommends |
|---|---|---|
| 90 to 100 | critical | Do not install. Treat as hostile until proven otherwise. |
| 60 to 89 | high | Do not install without remediation. |
| 30 to 59 | medium | Review before installing. |
| 10 to 29 | low | Likely acceptable. Review and proceed with awareness. |
| 0 to 9 | info | No significant risk detected. |

The label is bounded by the evidence on both sides. One critical finding (confidence
0.5 or more) keeps the label at high or above, whatever the arithmetic says. And the
label never rises more than one step above the most severe single finding: many medium
findings together can make a skill high, but not critical; many low ones stop at
medium. A finding whose confidence is under 0.5 counts one step lower for this purpose.

## Releases

A release is a signed version tag on `main` (`v1.0.0`) and a GitHub release that
carries five files:

| File | What it is |
|---|---|
| `skillwarden-X.Y.Z-py3-none-any.whl` | The package, ready to install |
| `skillwarden-X.Y.Z.tar.gz` | The source it was built from |
| `skillwarden-X.Y.Z.cdx.json` | The parts list (an SBOM, CycloneDX 1.5): the packages in `uv.lock`, which is what the tests ran with and what `uv sync` installs. The optional extras are not in it. A `pip install` of the wheel works out the dependencies afresh and may pick newer versions |
| `skillwarden-X.Y.Z.provenance.sigstore.json` | The signed statement of where and how the three files above were built |
| `skillwarden-X.Y.Z.sbom.sigstore.json` | The signed statement that ties the parts list to the wheel and the source archive |

**Verifying a release.** The files are built by the release workflow of this
repository, on GitHub's runners and not on anyone's own machine. With the GitHub CLI,
for any of the first three files:

```bash
gh attestation verify skillwarden-1.0.0-py3-none-any.whl --repo MaxsysLab/skillwarden \
  --signer-workflow MaxsysLab/skillwarden/.github/workflows/release.yml \
  --source-ref refs/tags/v1.0.0
```

A pass means that a run of that workflow, started by that tag, attested this exact
file. Without the last two options the check is much weaker: it passes for a file
attested by any workflow in the repository.

The statement about the parts list is checked on the wheel and the source archive, not
on the parts list itself, and always with `--predicate-type https://cyclonedx.org/bom`.
To check against the statements that came with the release, and not the copies GitHub
keeps, add `--bundle` with the matching `.sigstore.json` file: the provenance one as it
is, the SBOM one together with that `--predicate-type`.

A pass does not tell you that the code is free of faults, or who made the tag. The tag
is signed, and GitHub marks it Verified when the signature belongs to a key registered
on the tagger's GitHub account.

**Cutting a release** (maintainers).

Once, before your first release: register your signing key on your GitHub account as a
signing key (an authentication key is not enough), and set `user.email` to an address
that is verified on that account. Sign a commit with it and see that GitHub marks the
commit Verified. A tag GitHub cannot verify is refused by the workflow, and by then the
tag is public.

1. In one pull request, set the version in `pyproject.toml` and in
   `src/skillwarden/__init__.py`, and give the changes a dated entry in `CHANGELOG.md`
   (`## [X.Y.Z] - YYYY-MM-DD`, the day of the release). The checks fail if the three
   disagree, or if the entry uses Markdown the release notes cannot carry.
2. When it is merged and `main` is green, tag the commit `main` points at, and look at
   the tag before it leaves your machine:

   ```bash
   git fetch origin
   git tag -s vX.Y.Z origin/main -m "SkillWarden X.Y.Z"
   git cat-file -t vX.Y.Z    # must print: tag
   git push origin vX.Y.Z
   ```

3. The release workflow does the rest. It stops if the tag is lightweight, not verified
   by GitHub, not on a commit of `main` itself, or not named after the version in the
   files. It builds the package, writes the parts list, attests the files, and
   publishes the release with the changelog entry as its notes. Then it downloads the
   published files and checks them as a user would.

These checks catch mistakes. They are not a defence against someone who can push to the
repository, because the workflow that runs is the one at the tagged commit.

We do not move a published tag. A release that turns out wrong is followed by a new
one. If the workflow fails after the tag is pushed, re-run the failed jobs only. If the
fault is in the workflow file itself, the fix goes out as the next version.

## Environment variables

| Variable | Default | What it sets |
|---|---|---|
| `SKILLWARDEN_PROVIDER` | `auto` | The AI backend: `auto`, `claude_cli`, `anthropic`, `ollama` |
| `SKILLWARDEN_MODEL` | `claude-opus-5` | The model for the `anthropic` backend |
| `SKILLWARDEN_CLI_MODEL` | `opus` | The model alias for the `claude_cli` backend |
| `SKILLWARDEN_CLI_TIMEOUT` | `180` | Seconds allowed for one call through the CLI |
| `SKILLWARDEN_LLM_BATCH_CHARS` | `200000` | Characters of skill text shown in one call |
| `SKILLWARDEN_LLM_MAX_CHARS` | `3000000` | Characters shown in all calls together |
| `SKILLWARDEN_LLM_MAX_TOKENS` | `4096` | Reply length for the `anthropic` backend |
| `SKILLWARDEN_OLLAMA_URL` | `http://localhost:11434` | The Ollama server |
| `SKILLWARDEN_OLLAMA_MODEL` | `llama3.1` | The Ollama model |
| `SKILLWARDEN_OLLAMA_NUM_CTX` | `8192` | The Ollama context window, in tokens |
| `SKILLWARDEN_OLLAMA_TIMEOUT` | `120` | Seconds allowed for one Ollama call |
| `SKILLWARDEN_MAX_FILE_BYTES` | `2097152` | Largest file that is read (2 MiB) |
| `SKILLWARDEN_MAX_TOTAL_BYTES` | `52428800` | Largest skill that is read (50 MiB) |
| `SKILLWARDEN_MAX_COMPONENTS` | `2000` | Most files that are read |
| `SKILLWARDEN_MAX_ZIP_RATIO` | `100` | Zip-bomb guard: uncompressed to compressed ratio |
| `SKILLWARDEN_ZIP_RATIO_FLOOR_BYTES` | `1048576` | The ratio applies above this uncompressed size |
| `SKILLWARDEN_NETWORK_TIMEOUT` | `20` | Seconds allowed for a fetch or the OSV lookup |
| `SKILLWARDEN_LOG_LEVEL` | `WARNING` | Log level |
