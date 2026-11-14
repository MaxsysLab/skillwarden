# Governance

This file says who is responsible for SkillWarden, how decisions are made, and how a
contributor grows into a maintainer. It describes what is actually practiced today.

## Who stands behind SkillWarden

- **Publisher:** Maxsys International Incorporated, a nonprofit (maxsys.org), publishes
  SkillWarden as an open-source project through the MaxsysLab organization on GitHub.
- **Builder:** CSEAM Technology Corporation builds SkillWarden and contributes its work to
  the project.
- **Contributors:** anyone who opens an issue or a pull request. Students, interns, and
  volunteers are the people this project is meant for.

The publisher and the builder manage the project together on an interim basis, until a
dependable, dedicated maintainer is appointed. The people who hold each role today are
listed in [MAINTAINERS.md](MAINTAINERS.md).

## Roles

- **Program lead.** The accountable person at the publisher. Owns what goes public,
  signs off each release, and is the last step for Code of Conduct incidents and
  security disclosures.
- **Maintainers.** Merge pull requests and prepare releases. They decide by lazy
  consensus: a change can merge once it is approved, its checks pass, and no maintainer
  has a standing objection. Ties go to the program lead.
- **Reviewers.** Review and approve pull requests in an area they know.
- **Triagers.** Label, reproduce, and route issues. No merge rights needed.
- **Contributors.** Everyone else who takes part.

## How decisions are made

- **Routine changes** (bug fixes, documentation, small features that have an issue):
  maintainer approval and green checks, then merge.
- **Significant changes** (breaking changes, a new dependency, architecture, this
  document): a short written proposal in an issue, discussion in the open, and a
  decision by the maintainers. The program lead breaks ties.
- **Releases:** a maintainer prepares the release and its changelog; the program lead
  signs off; then the tag is published.

Everything substantive is discussed and recorded in the open, in issues and pull
requests.

## Growing into a role

Responsibility is earned by sustained, good contribution, and granted in the open.
Work on documentation, triage, community, releases, and security counts as much as code.

| Role | What you do | How you get there |
|---|---|---|
| Contributor | Open issues and pull requests, help others | Make a contribution |
| Triager | Label, reproduce, and route issues | Sustained, careful triage; nominated by a maintainer |
| Reviewer | Review and approve pull requests in an area | A track record of good reviews there; nominated and agreed by the maintainers |
| Maintainer | Merge, release, mentor, set direction | Sustained, broad, trusted contribution; nominated, sponsored by a maintainer, and agreed by the maintainers |
| Emeritus | Honored former maintainer | Three months without activity, or stepping down |

To advance, a maintainer nominates you publicly in an issue, citing specific work. A
maintainer agrees to mentor you through the change. The maintainers decide in the open.
Then access is granted and [MAINTAINERS.md](MAINTAINERS.md) is updated.

A maintainer or reviewer with no contributions or communication for three months moves
to emeritus, so that the list of maintainers stays honest. Returning is quick. Stepping
down at any time is normal and respected.

## Code of Conduct

The [Code of Conduct](CODE_OF_CONDUCT.md) applies in every project space. Reports go to
the address in that file. The program lead owns serious incidents, and the reporter's
confidentiality is protected.

## Changing this document

A change to governance is a significant change: proposed in an issue, discussed in the
open, and decided by the maintainers and the program lead.
