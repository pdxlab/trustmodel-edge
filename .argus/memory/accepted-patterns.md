# Accepted patterns

Things that look wrong and are not. Keep this list short — every entry is a
finding the verifier will refuse to confirm.

## Known gaps that are already tracked — report only if the PR makes them worse

- **`persist_credentials` is not atomic.** Its docstring in
  `src/edge/identity.py` says it will "atomically write all four files"; it
  performs four sequential `write_text` calls with an `os.chmod` between them.
  A crash mid-write leaves a half-rotated credential set. This caused the
  xspan QA outage in **TRUS-2374** and is known. Flag a PR that adds a fifth
  non-atomic write or widens the window; do not re-report the existing shape.

- **`/rotate` invalidates the previous certificate immediately.** A lost
  rotation response, or two replicas sharing an identity rotating at once,
  can lock Edge out. Tracked as **TRUS-2376**. Known, not a new finding.

## Not findings

- **No retry on the first enrolment attempt.** Enrolment is a one-shot at
  startup by design; the supervisor restarts the pod.
- **Helm templates duplicate labels across resources.** `_helpers.tpl` is the
  single source; the repetition is how Helm works.
- **`src/edge/engine/compiler.py` builds policy structures eagerly at load.**
  Intentional — the evaluator must not do work per request.
