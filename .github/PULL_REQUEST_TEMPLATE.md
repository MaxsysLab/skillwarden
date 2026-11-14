## What and why
<!-- What does this change, and why? Link the issue it closes: Closes #123 -->

## Checklist
- [ ] I filed or linked an issue for anything larger than a small fix
- [ ] `make lint typecheck test` passes on my machine
- [ ] Tests added or updated. For a rule change: the harmless text stays quiet, every line in `tests/unit/test_rule_coverage.py` still fires, and I have asked for someone else to try to get an attack past it
- [ ] If a rule or the scoring changed, `make audit` passes
- [ ] The README is updated if behaviour changed
- [ ] No new dependency, or the issue explains why one is needed
- [ ] Every commit is **signed off** (`git commit -s`, the DCO)
- [ ] I followed the [Code of Conduct](../CODE_OF_CONDUCT.md)
