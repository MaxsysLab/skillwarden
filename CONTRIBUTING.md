# Contributing to SkillWarden

Welcome. This is a learning-friendly project published by Maxsys International
Incorporated through MaxsysLab. Students and interns are the intended contributors, so
questions are encouraged and small pull requests are great.

## New to open source? Start here

1. Run it on your own machine. The README's "Start in a few minutes" needs no API key.
2. Pick an issue labelled **good first issue**. Comment on it so others know you are
   working on it. If nothing fits, ask in a new issue and a maintainer will suggest one.
3. Read "The two rules that matter most" below.
4. Open a small pull request. A maintainer will review it and help you get it merged.

You do not have to write code to contribute. A harmless line that was flagged, a
hostile line that was missed, clearer documentation, and help answering other people's
issues all count.

## Ground rules

- Be kind and follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- **File an issue before a large pull request.** Small fixes (typos, obvious bugs) can
  go straight to a pull request. For anything substantial, open an issue first so we
  can agree on the approach.
- Security problems are never reported in a public issue. Follow [SECURITY.md](SECURITY.md).

## Prerequisites

- Python 3.12 or 3.13
- [uv](https://docs.astral.sh/uv/) (`uv --version`)

## Build, test, run

```bash
make dev          # install with the development and YARA extras
make test         # the test suite
make lint         # ruff
make typecheck    # mypy --strict
make scan-demo    # scan the bundled malicious sample
make audit-fetch  # fetch the published benign skills and run the false-positive audit
make audit        # the same audit on the copy already fetched, with no network
```

## How the code is laid out

```
src/skillwarden/cli.py            the command: skillwarden scan
src/skillwarden/engine.py         the scan: input, analyzers, AI pass, score, result
src/skillwarden/input_handler.py  folders, files, zips and URLs, with their limits and refusals
src/skillwarden/analyzers/        one module per threat category; base.py has the rule type
src/skillwarden/semantic/         the optional AI pass and its second, refuting call
src/skillwarden/providers/        the AI backends behind one small interface
src/skillwarden/report/           scoring, and the terminal, JSON, Markdown and SARIF reports
scripts/fp_audit.py               the false-positive audit over published benign skills
tests/                            the tests, and small sample skills in tests/fixtures
```

## The two rules that matter most

**A scan that did not read everything is never a pass.** If a file could not be read,
a lookup could not be made, or the AI pass did not fully run, the scan is incomplete
and the command exits 2. When you add a step that can fail, make its failure visible
in the result. Do not catch an error and carry on as if the step had run.

**The tool stays small enough to read.** SkillWarden has six dependencies and about
five thousand lines, and a person can read all of it. Prefer a few lines of our own to
a new dependency, and discuss first if you think one is needed.

## Changing a rule

Read this before you touch a rule. We learned it the hard way.

A rule that fires on harmless text is a false alarm. The natural fix is to make the
rule more precise, and that is where the danger is: a rule made quieter may have been
made blind. For the first release we made ten rules more precise, wrote tests for each,
and watched the false alarms go away. An independent reviewer then got real attacks
past the new rules, twice. Our tests had only the wordings we had thought of. The rules
went back to what they were.

So a rule change needs three things:

1. **The harmless text that must stay quiet**, as a test. Write your own line with the
   same shape as the text you found. Do not copy text from someone else's skill.
2. **Every attack line in `tests/unit/test_rule_coverage.py` still firing.** That file
   is the floor. Add the attacks you can think of for your rule, in several wordings:
   quoted, glued together with `${IFS}`, punctuated, split across arguments.
3. **A second person who tries to break it.** Ask in the pull request for someone other
   than you to run the old rule and the new one on attack lines of their own and look
   for one the old rule caught and yours misses. Also time your pattern on a very long
   line: a pattern that takes seconds on 100,000 characters can stall a scan.

Then run `make audit`. If your change removes one of the known false alarms, the audit
tells you to take it off the list in `scripts/fp_audit.py`.

## Making a change

1. Fork the repository and create a branch from `main`.
2. Make your change. Keep pull requests focused and small.
3. Add or update tests, and run `make lint typecheck test`.
4. Write commit messages in the [Conventional Commits](https://www.conventionalcommits.org/)
   style, for example `fix: handle an empty archive`.
5. **Sign off every commit** (see below).
6. Open a pull request, fill in the template, and link the issue it closes.

## Developer Certificate of Origin (DCO)

This project uses the **DCO**, not a contributor licence agreement. By signing off, you
certify that you wrote the contribution or have the right to submit it under the
project's licence. The full text is at <https://developercertificate.org/>. Sign off by
adding a `Signed-off-by` line to each commit:

```bash
git commit -s -m "fix: handle an empty archive"
```

This appends `Signed-off-by: Your Name <your@email>`, matching your git configuration.
A check on every pull request enforces it. Fix a missing sign-off with
`git commit --amend -s`, or `git rebase --signoff` for a series.

## Good first areas

- A hostile wording that a rule misses today, added to the coverage file with the fix.
- One false alarm removed, the careful way described under "Changing a rule".
- Tests for a part of the code that has few.
- Clearer wording in a report or an error message.

## Review and merge

We aim to give a first response within 3 business days. Reviews are about the code,
never the person. Once a change is approved and every required check passes, a
maintainer merges it.

## Growing here

Sustained, good contribution earns responsibility. [GOVERNANCE.md](GOVERNANCE.md)
describes the path from first contribution to maintainer. SkillWarden is looking for a
dedicated maintainer, so that path is real.
