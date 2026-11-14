---
name: False alarm
about: Something harmless was flagged, or was rated too high
labels: ["false-alarm", "needs-triage"]
---

**The line that was flagged** (and the kind of file it is in)

**The rule that fired** (for example `TM-001`) **and the severity**

**Why the line is harmless**

**Where it comes from** (a published skill and its address, if it is public)

**Was the AI pass on?** (yes / `--no-llm`). If yes, did it mark the finding as a likely false positive?
