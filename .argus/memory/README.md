# Repository memory

Facts about **this** codebase that a reviewer seeing it for the first time
would otherwise get wrong. The engine reads every file in this directory and
puts it in the reviewer's prompt, and the verifier treats a finding that
contradicts this memory as **not confirmed**.

So the bar is high: write what is *true and settled*, not what is merely
current. A wrong entry here silently suppresses real findings.

- `conventions.md` — how this codebase does things on purpose
- `accepted-patterns.md` — things that look like bugs and are not
