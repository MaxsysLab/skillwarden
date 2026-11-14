# SkillWarden

An AI agent skill is a folder of instructions and scripts that an agent will read and
follow. Installing one is an act of trust. SkillWarden reads a skill before you install
it and tells you what it found: a risk score from 0 to 100, a plain label, and the
lines behind each finding. It reads the skill. It never runs it.

We built it for our own software lab, where AI agents work with skills every day and
someone has to answer "is this one safe?" before a new one is adopted. It is released
here for anyone who has the same question.

Two things about it are deliberate.

**It will not call a partial scan a pass.** If a file could not be read, a lookup could
not be made, or a requested check did not run, the scan is reported incomplete and the
command exits with an error. You do not need to ask for this. It is the default.

**It is small enough to read.** About 4,500 lines of Python and six dependencies, with
no agent framework underneath. A tool that guards what you install should be one you
can inspect, and one person can read all of this in an afternoon.

## What it does

It looks at a skill in two passes.

The first pass is fixed rules, and it is the same every time: 67 rules and several
deeper checks across 17 kinds of threat, among them instructions that try to override
the agent or hide things from the user, credentials being read and sent away, installs
piped straight into a shell, destructive commands, untrusted input reaching code
execution, and unsafe MCP server settings. It also looks up the skill's pinned
dependencies for known vulnerabilities.

The second pass is optional and uses an AI model. Fixed rules cannot weigh intent, and a
model can. It may add findings the rules missed. It may also mark a finding as a likely
false alarm, but only after a second call, asked to argue the opposite, agrees and
quotes its evidence. It never removes a finding, and the model is given no tools, so
the text of a hostile skill has nothing to act through.

The result comes as terminal text, JSON, Markdown or SARIF, with exit codes made for an
install gate or a CI job.

## Start in a few minutes

You need Python 3.12 or 3.13 and [uv](https://docs.astral.sh/uv/).

1. Get the code and install it:

   ```bash
   git clone https://github.com/MaxsysLab/skillwarden.git
   cd skillwarden
   uv sync
   ```

2. Scan the hostile sample that ships with it, to see what a bad result looks like:

   ```bash
   uv run skillwarden scan tests/fixtures/malicious_skill --no-llm
   ```

   It reports CRITICAL, 100 of 100, lists twelve findings with their lines, and exits
   with code 1.

3. Scan the harmless sample:

   ```bash
   uv run skillwarden scan tests/fixtures/benign_skill --no-llm
   ```

   No findings, exit code 0.

4. Scan a skill of your own. The target can be a folder, a single file, a `.zip`, or a
   GitHub, GitLab or `https` address:

   ```bash
   uv run skillwarden scan path/to/your-skill --no-llm
   ```

`--no-llm` keeps to the fixed rules, which need no account and no key. Leave it off to
add the AI pass; see [The AI pass](#the-ai-pass) for what that needs.

## Reading the result

| Exit code | Meaning |
|---|---|
| `0` | The scan is complete and the label is below your threshold |
| `1` | The scan is complete and the label is at or above your threshold |
| `2` | The scan is incomplete, the input could not be read, or the command was wrong |

The threshold is `--fail-on`, and its default is `high`. Use `--fail-on medium` for a
stricter gate, or `--fail-on none` to always get 0 or 2.

An incomplete scan still shows whatever it found, and says what it could not do. Treat
it as "not cleared", whatever the score. The usual causes are a file over the size
limit, an archive inside the skill, a file that cannot be read, the AI pass having no
model to call, and the vulnerability lookup having no network. Each has a way through:
`--no-llm` for a scan without the AI pass, `--no-osv` for a scan without the lookup.
Both are stated in the report, so a reader knows what was not checked.

The labels are critical, high, medium, low and info. Many small findings can raise a
label one step above the most serious single finding, and no further: a pile of medium
findings can make a skill high, but only a high or critical finding can make it
critical.

## Using it as a gate

In a CI job or an install script, let the exit code decide:

```bash
uv run skillwarden scan ./skills/new-skill --no-llm --format sarif --output scan.sarif
```

A skill you have reviewed and accepted can keep its known findings in a baseline file,
so the gate fails only on something new:

```bash
uv run skillwarden scan ./skills/new-skill --no-llm --baseline accepted.yaml
```

The baseline format, every reason a scan can be incomplete, what is refused and why,
and every setting are in [docs/REFERENCE.md](docs/REFERENCE.md).

## The AI pass

Without `--no-llm`, SkillWarden asks a model to review the skill after the fixed rules
have run. It uses, in this order: an Anthropic API key if `ANTHROPIC_API_KEY` is set;
the Claude Code command line if it is installed and signed in, which needs no key; a
local Ollama server if one is running. If none is available, the scan is incomplete and
says so.

The whole skill is shown to the model. A skill that fits in one call is reviewed whole.
A larger one is reviewed in parts, and in that case the model can add findings but
cannot lower any, because what makes a line dangerous may be in a part it was not shown.

## Where it stands

We wrote it in mid-2026 for our own lab, to vet skills and skill libraries before they
are adopted. For this release it was tested as follows, on 14 November 2026.

It has 778 automated tests, with strict type checking and lint, all passing on Python
3.12 and 3.13. Among them are about 150 attack lines, plain and disguised, that the
fixed rules must keep catching.

**The fixed rules are strict, and they raise false alarms.** We ran them over the 20
skills Anthropic publishes at [anthropics/skills](https://github.com/anthropics/skills)
(commit `2c5958e`), which we take to be harmless. Fourteen came back clean, one low,
one medium and one high. Two came back critical, and both are false alarms: a large
documentation skill whose pages discuss security (a comment that names a key file, a
warning against `curl | sh`), and a spreadsheet skill whose script hands a file name
to another program. One more could not be scanned to completion because it carries an
archive. If a skill you trust is flagged like this, read the findings, and if you
agree they are harmless, record them in a baseline file so the gate fails only on
something new.

We tried to do better for this release. We made ten of the rules more precise, the
false alarms went away, and an independent reviewer then showed, twice, that the more
precise rules also missed real attacks. So the rules ship as they were. A rule that
cries wolf is a nuisance; a rule that misses is a hole. Making them more precise
without making them blind is real work, and it is open for contribution, one rule at a
time (see [CONTRIBUTING.md](CONTRIBUTING.md)). The audit behind these numbers is in the
repository (`make audit-fetch`) and runs every week against the skills as published
that day.

We ran the AI pass on six of those skills and on the four bundled samples, through the
Claude Code command line. It completed on all ten, the largest being 1.1 million
characters reviewed in seven calls. On the hostile samples it added findings the rules
had missed. On three harmless skills it marked findings as likely false alarms, with
the evidence for each.

What we have not tried: the Anthropic API backend with a real key, and a real Ollama
server (it was tested against a stand-in). If you use one of those, a first scan of
the bundled samples will tell you whether it works for you.

Its known limits are stated. Archives inside a skill are not unpacked, and files over
2 MiB are not read; in both cases the scan says so and is incomplete. The fixed rules
read text and cannot weigh intent. And a file with one very long line of the right
words can make a scan slow: a script holding a single 80,000-character line took 13
seconds here, and the time grows about four-fold each time the line doubles. The
result is not wrong, it is late, so in a gate give the scan a time limit.

## How it compares

SkillWarden was written after studying
[SkillSpector](https://github.com/NVIDIA/SkillSpector), NVIDIA's open-source scanner
for the same job, and it follows the same approach and threat categories. SkillSpector
does more: it reads larger files, looks inside archives, inspects dependencies and
supports many more AI providers. If you need that breadth, use it.

SkillWarden is the small one. It does the core of the job in a few thousand lines you
can read, with six dependencies, and it treats an incomplete scan as a failure without
being asked.

## Development

```bash
make dev          # install with the development and YARA extras
make test         # the tests
make lint         # ruff
make typecheck    # mypy --strict
make audit-fetch  # fetch the published benign skills and run the false-positive audit
```

Pull requests are welcome, small ones especially. A harmless line that gets flagged and
a hostile line that gets missed are both useful reports, and there is an issue template
for each. [CONTRIBUTING.md](CONTRIBUTING.md) explains how a rule change is tested. If
you find a security problem in SkillWarden itself, please tell us privately first, as
[SECURITY.md](SECURITY.md) describes.

## Who stands behind it

Published as open source by Maxsys International Incorporated, a nonprofit
(maxsys.org), through [MaxsysLab](https://github.com/MaxsysLab). Built by CSEAM
Technology Corporation for its own software lab, and released for anyone to use.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

Copyright 2026 Maxsys International Incorporated.
