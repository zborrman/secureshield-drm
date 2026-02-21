## Summary
<!-- What does this PR do? (1–3 bullet points) -->
-

## Type of change
<!-- Mark all that apply -->
- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / code quality
- [ ] CI / tooling
- [ ] Documentation

## How was this tested?
<!-- Describe the test plan, or reference test files added/changed -->
- [ ] New unit tests added (`backend/tests/`)
- [ ] Existing tests pass locally (`pytest tests/ -v`)
- [ ] Manually verified in the browser

## Backend checklist
- [ ] New endpoints documented in `openapi.yaml`
- [ ] DB model changes handled (new columns / tables)
- [ ] No plaintext secrets or credentials committed
- [ ] Redis / S3 usage mocked in tests (`fake_redis`, `mock_s3` fixtures)

## Frontend checklist
- [ ] No hardcoded API URLs (use `process.env.NEXT_PUBLIC_API_URL`)
- [ ] Right-click / context-menu disabled on protected content renderers
- [ ] New components added to `AdminDashboard.tsx` if admin-facing

## Screenshots (if UI changes)
<!-- Drag & drop before/after screenshots here -->

## Related issues
<!-- Closes #issue-number -->
