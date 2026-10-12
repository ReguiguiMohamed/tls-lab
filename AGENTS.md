# Rules for AI assistants

- The only scope is this repository and the lab's local services. No external targets.
- Run `docker compose run --rm lab` before every commit. Every check must pass.
- Every new observation in the report gets its check in `lab.sh`.
- Never commit `out/`, keys, key logs or real passwords.
- No new protocol families. `PLAN.md` fixes the scope.
- Docs in English, short sentences, nothing unverified.
