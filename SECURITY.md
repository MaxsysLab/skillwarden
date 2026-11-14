# Security Policy

SkillWarden is a security tool, so a weakness in it can become a weakness in whatever
it guards. We want to hear about one before anyone else does.

## Reporting a vulnerability

**Please do not report security vulnerabilities through public GitHub issues or pull
requests.**

Report privately through
[GitHub Private Vulnerability Reporting](https://github.com/MaxsysLab/skillwarden/security/advisories/new)
(preferred), or by email to **security@maxsys.org**.

Please include a description of the issue, steps to reproduce or a proof of concept,
the affected version, and any fix you would suggest. If you would like credit, tell us
how to name you.

## What counts as a vulnerability here

- A way to make a scan report **complete** when some input was not read, or when a
  requested part of the scan did not run.
- A way for the content of a scanned skill to run code, reach the network, or read
  files on the machine that runs the scan. SkillWarden reads skills; it never runs them.
- A way for a scanned skill to forge or hide lines in a report, in any output format.
- A way to make the optional AI pass lower a finding without the evidence it requires.

## What does not need a private report

A rule that misses an attack, or raises a false alarm, is ordinary work on the rules.
Open an issue with the "Missed detection" or "False alarm" template and include the
smallest text that shows it. If the miss is one you would rather not publish yet,
report it privately and we will treat it with the same care.

## What to expect

- An **acknowledgement** within **7 days** of your report.
- An initial **severity assessment** and a triage decision shortly after.
- We work on a fix under a coordinated **embargo**. The standard disclosure window is
  **90 days** from your report, or sooner once a fix is released, whichever comes first.
- On release we publish a **GitHub Security Advisory**, request a CVE where warranted,
  and credit reporters who want it.

## Supported versions

| Version | Supported |
|---|---|
| latest | yes |
| older | best effort |

## Safe harbor

We will not pursue or support legal action against researchers who act in good faith,
follow this policy, avoid privacy violations and service disruption, and give us
reasonable time to respond before any public disclosure.
