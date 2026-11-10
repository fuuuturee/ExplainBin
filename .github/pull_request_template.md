## Summary

Describe the change and the motivation.

## Type of change

- [ ] Bug fix
- [ ] Parser hardening
- [ ] New or changed finding rule
- [ ] UI change
- [ ] Report change
- [ ] Documentation
- [ ] Build or CI

## Testing

- [ ] `cmake --build` succeeds
- [ ] `ctest --output-on-failure` passes
- [ ] Added or updated tests for the change
- [ ] CLI smoke test on a real system binary

Describe the environment used (Windows version, compiler, Qt version).

## Safety checklist

- [ ] The analyzed file is never executed, loaded, mapped or uploaded
- [ ] New parsing paths validate offsets and sizes before access
- [ ] Counts and recursion are bounded
- [ ] Untrusted strings are sanitized before reaching UI or reports
- [ ] No live malware or sensitive binaries are included
- [ ] New findings include evidence, benign explanations and next steps
- [ ] No combined malware score or misleading verdict was added

## Documentation

- [ ] README or docs updated
- [ ] New rule documented in `docs/RULES.md`

## Screenshots (UI changes)

Add before/after images if the change is visual.
