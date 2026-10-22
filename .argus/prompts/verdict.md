# Argus — Verdict & Report Format

> **Local divergence from `karlmehta/argus@v1` (TRUS-1955).** The "the summary IS
> the review body" rule below is a pdxlab addition. Upstream stated the body
> requirement only on the request-changes branch, so the approve and comment paths
> emitted a stub review ("see summary below") with the findings in a separate
> comment — observed twice, on aurora-metrics-v2#206 and trustmodel-python-sdk#20.
> **Re-apply this section when re-vendoring from upstream.**

## Inline comments
Post inline comments **only** for `blocker`/`major`/`minor` findings, at the exact
`path:line`. Format each:

> **[severity] skill:** what's wrong — why it matters. *Suggested fix:* …

Skip inline comments for `nit`s (roll them into the summary) and for `question`s
unless a specific line is needed.

## Summary review body
Post one summary with this shape:

```
## 🛡️ Argus review

**Verdict:** <REQUEST CHANGES | COMMENT | APPROVE>  ·  <n blocker · n major · n minor · n nit>

### Findings
| Sev | Skill | Location | Finding |
|-----|-------|----------|---------|
| 🔴 blocker | security | api/views.py:212 | Missing tenant scope → IDOR |
| 🟠 major   | correctness | tasks.py:88 | Non-atomic read-modify-write |
| 🟡 minor   | tests | — | New branch in `accept()` is untested |

### Questions
- <things you weren't sure enough to call findings>

### 📝 Memory suggestion  (optional)
- <a convention/accepted-pattern worth recording, for a human to merge>
```

Severity icons: 🔴 blocker · 🟠 major · 🟡 minor · ⚪ nit.

## The summary IS the review body — never a separate comment
Pass the summary as the body of the `gh pr review` call itself — write it to a file
and use `--body-file`, or pass `--body`. This applies to **every** verdict,
`--approve` included.

Do **not** post a stub review ("see summary below", "see summary comment for
details") and put the findings in a separate `gh pr comment`. The Reviews tab is
the first place a human looks, and a pointer there is useless: whoever is scanning
reviews sees a verdict with no reasoning attached, and an approval with an empty
body is indistinguishable from a reviewer that did nothing.

If the body is getting long, cut low-confidence findings and nits — do not split it
across two places. One review, one body, everything in it.

## Choosing the verdict
Read `verdict.allow_approve` and `verdict.gate` from `config/argus.yml`.

1. **Any confirmed `blocker` or `major`** →
   `gh pr review <n> --request-changes --body-file <summary>`
2. **Otherwise, if `allow_approve: true`** AND zero blocker/major AND you would
   genuinely sign off →
   `gh pr review <n> --approve --body-file <summary>`
   - Do **not** approve a PR authored by a bot/automation account.
   - Do **not** approve solely to unblock a merge. If you'd hesitate as a human
     reviewer, use `--comment` instead.
3. **Otherwise** → `gh pr review <n> --comment --body-file <summary>`

Every branch carries the summary in the review body. A review with an empty or stub
body is a failed review even when the verdict itself is right.

The default configuration ships with `allow_approve: false`. Enabling it is a
deliberate governance choice by the repository owner — see `docs/governance.md`.
