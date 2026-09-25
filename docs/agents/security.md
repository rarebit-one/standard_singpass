# Security notes

Moved verbatim from `AGENTS.md` in the P3 trim, except the last bullet, which was corrected (see the PR that introduced this file).

## Security Notes

- Private JWKS keys live in env vars / secret managers — never the repo.
  The `validate_jwks` rake task refuses public-only keys (missing `d`).
- `body_excerpt` in `Client` only surfaces a fixed allowlist of FAPI /
  OAuth error fields (`error`, `error_description`, `trace_id`, `id`,
  `state`) to error messages — Singpass error payloads can carry NRIC /
  email / other PII alongside the OAuth fields.
- `SAFE_ERROR_FIELDS` is the load-bearing allowlist; do not widen it
  without auditing what Singpass returns in error bodies.
- `bundle exec brakeman --no-pager --force` runs as part of the pre-push
  lefthook checks (`lefthook.yml`). `bundle exec bundler-audit --update` runs
  in CI (`.github/workflows/ci.yml`), not in lefthook.
