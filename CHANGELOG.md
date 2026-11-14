# Changelog

All notable changes to SkillWarden are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

Nothing has been tagged yet. This section becomes the first public release.

SkillWarden was built inside our own software lab before it was published, where it
stood at an internal version 0.1.0. This repository starts from the tool as it is after
the release work. What follows is what changed in that work, to make it fit for anyone
to rely on.

### What it is

- A command, `skillwarden scan`, that reads an AI agent skill (a folder, a file, a zip,
  or a git or https address) and reports a risk score from 0 to 100, a severity label
  and the findings behind it, as terminal text, JSON, Markdown or SARIF 2.1.0.
- Nineteen analyzers across seventeen threat categories: pattern rules for prompt
  injection, data exfiltration, supply chain and ten more; an AST check for dangerous
  code; taint tracking; two checks for MCP configuration; optional YARA signatures;
  and a live lookup of known vulnerabilities in pinned dependencies (OSV).
- An optional AI pass that can add findings the fixed rules miss, and can lower a
  finding only after a second, refuting call confirms it with quoted evidence.
- Exit codes meant for a gate: 0 clean, 1 at or above the threshold, 2 incomplete.
  A scan that could not read everything is never reported as a pass.

### Changed

- **The AI pass reads the whole skill.** It used to show the model the first 6,000
  characters of each file, and reported the scan incomplete when a file was longer,
  which on real published skills was nearly always. Every character is now shown: in
  one call when the skill fits, otherwise in parts. A skill reviewed in parts can gain
  findings but never has one lowered, because lowering a finding needs the whole skill
  in one view. `SKILLWARDEN_LLM_BATCH_CHARS` and `SKILLWARDEN_LLM_MAX_CHARS` set the
  size of one call and of all calls together.
- **A vulnerability lookup that cannot run is no longer a silent pass.** If a skill
  pins dependencies and osv.dev cannot be reached or its answer cannot be read, the
  scan is incomplete. To scan without the lookup, pass the new `--no-osv`; the report
  then says which dependencies were not checked. **If you scan offline, add `--no-osv`.**
- **The label is bounded by the evidence.** It can rise one step above the most severe
  single finding and no further. Many medium findings together can make a skill high;
  they can no longer make it critical.
- **The fixed rules are unchanged.** For this release ten of them were made more
  precise to remove false alarms on published skills. Two independent reviews showed
  that the more precise rules missed real attacks, so the change was taken back. What
  remains of it is a set of about 150 attack lines, plain and disguised, that the rules
  must keep catching (`tests/unit/test_rule_coverage.py`).
- **The false-positive audit names what it knows.** It prints the commit of the corpus
  it measured. Two published skills the rules rate critical wrongly, and one that
  carries an archive, are named in the script and reported apart; any other benign
  skill that rates critical still fails the audit.

### Fixed

- **The AI pass through the Claude Code CLI gives the model nothing to act with.** The
  text of a hostile skill is passed to a model; that model now has no tools, no MCP
  servers and none of the machine's settings.
- **The AI pass no longer fails on its own category names.** The model was never told
  which categories the checker accepts, so a reply that invented one failed the whole
  pass. The prompt now lists them.
- **The Ollama backend sets its context window.** Ollama shortens a prompt that is too
  long without saying so. The window is now set on every call
  (`SKILLWARDEN_OLLAMA_NUM_CTX`), each prompt is sized to fit it, and a prompt that
  could exceed it is refused before it is sent.
- **Hostile file names and contents have less room to write the AI pass's own prompt.**
  In file headers a name is written with its newlines and backticks escaped, and each
  file sits in a code fence longer than any run of backticks inside it.
- **A backend that counts bytes is sized in bytes.** Ollama's limit is checked in
  bytes, so prompts for it are now planned in bytes too, and a skill written mostly in
  a non-Latin script can be reviewed to the end.
- **A reply from the vulnerability lookup that is malformed or partial fails the
  lookup** and is no longer read as "no advisories".
- The SARIF report names this repository as its information address.
- The offline false-positive audit no longer makes a network call.

### Project

- Stated who stands behind the project: published by Maxsys International
  Incorporated through MaxsysLab, built and contributed by CSEAM Technology
  Corporation.
- Licensed under Apache-2.0, with an acknowledgement of NVIDIA's SkillSpector, the
  project SkillWarden was written after studying.
- Added the community files: code of conduct, security policy, support, governance,
  maintainers, issue and pull request templates, code owners.
- Checks on every pull request: lint, strict types and tests on Python 3.12 and 3.13,
  the two bundled samples scanned, sign-off (DCO), licence metadata (REUSE), dependency
  review, secret scan, pinned actions, and the OpenSSF Scorecard. Weekly: a dependency
  audit and the false-positive audit against the benign skills as published that day.

### Known limits

- The fixed rules raise false alarms on harmless skills whose text or scripts look like
  the things they watch for. On Anthropic's 20 published skills, two rate critical and
  one high. A baseline file records findings you have reviewed and accepted.
- A file with one very long line of the right words can make a scan slow: 13 seconds
  for an 80,000-character line, about four times longer each time the line doubles.
  The result is not wrong; it is late. Give the scan a time limit in a gate.
- In the list of findings shown to the model, a file name is written as it is. A name
  that contains a newline can add lines to that list. It cannot lower a finding by
  itself: that still needs a second call that names the exact finding and quotes its
  evidence.
- On a backend with a small context window, a skill full of long runs of backticks
  makes the AI pass fail, and the scan is incomplete.

- A skill that bundles an archive (a zip, a tarball, an Office file) cannot be scanned
  to completion: archives inside a skill are not unpacked, and the scan says so.
- The fixed rules read text. They are strict with documentation that discusses
  security, and they cannot weigh intent. That is what the AI pass is for.
- A skill too large for one call to the model is reviewed in parts, and in that case
  the AI pass does not lower any finding.
- The Ollama backend has been tested with a stand-in server only, not with a real one.
  Its default context window is small; raise `SKILLWARDEN_OLLAMA_NUM_CTX` to what your
  model allows.
- The Anthropic API backend has not been run with a real key.
