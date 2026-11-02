# Session rule ownership implementation plan

> **For agentic workers:** Use the executing-plans and test-driven-development skills. Get one fresh independent review of the complete branch delta.

**Goal:** Implement todo 8004c027 without expanding any host-approved network scope.

**Architecture:** Preserve separate rule rows per session and a separate uniqueness constraint for global rules. Carry authenticated session identity from the existing proxy login into rule evaluation; never select the newest session or union grants by client label.

**Tech stack:** Existing Go, SQLite, HTTP and SOCKS5 handlers; no new dependencies.

**Spec:** Theo's approved todo 8004c027 task. Baseline: `origin/dotfiles` at `1d1e518`. Evidence: `.handoff/codex-proxy-rule-fixture.py` (preserve unchanged).

## Constraints and decision

- Temporary databases and fake clients only; no live credentials, proxy edits, host execution, deployment or permission widening.
- Keep client labels, global rule priority and deny precedence; cover expiry, revocation, heartbeat, cleanup and existing databases.
- Theo approved unique-secret binding: only a uniquely matching live registered secret identifies a session. Missing/shared secrets receive no session grants. Preserve global rules and existing login policy.
- Feature branch commits, push and PR against `dotfiles` are authorized by CLAUDE.md; never force-push, merge, tag or release.

## Task 1: Storage ownership and migration

- [x] Add public CRUD regressions for identical rules in concurrent sessions, identical global/session rules, duplicate entries within one session, session upsert/delete/expiry/heartbeat, and global create/import/pending approval.
- [x] Verify failures with `GOMAXPROCS=2 go test -mod=readonly -p 2 ./internal/greyproxy -run 'Test(SessionRuleOwnership|SessionRuleMigration|GlobalRuleOwnership)' -count=1`.
- [x] Rebuild the rules table in an atomic new migration, preserving IDs, fields, indexes, sequence and log references. Use partial unique indexes for global and session scopes. Restrict global deduplication and expired replacement to global rows.
- [x] Verify old-schema migration through `DB.Migrate`, including rerun, foreign-key references and new session registration. Run the focused command again.

## Task 2: Authenticated rule evaluation (approved)

- [x] Add real public-entry regressions using session API/CRUD, Auther and Bypass through HTTP and SOCKS5 fake clients: same label, different secrets, overlapping and distinct grants, empty grants, ambiguous identities, expiry and deletion.
- [x] Observe failures before changing authentication or matching.
- [x] Implement the approved identity design in client-secret lookup, authenticator, rule matcher and all approval rechecks. Session allow-all must remain owned by its session and must not defeat explicit denials. Document compatibility requirements.
- [x] Run affected Go tests with `GOMAXPROCS=2`, `-mod=readonly` and `-p 2`.

## Review focus and completion

- [x] Test missing/shared secrets and stale identity after deletion, expiry, secret removal or rotation; no fallback to another session.
- [x] Test global rules and denies despite session overlap and allow-all.
- [x] Test migration from version 16 with existing audit references and rollback on failure.
- [x] Test public global rule creation/import/pending approval while identical session rules exist.
- [x] Test approval rechecks retain the original session identity.
- [x] Run one full `GOMAXPROCS=2 go test -mod=readonly -p 2 -race -count=1 ./...`, build, and available repository lint. Report exact failures and unavailable checks.
- [x] Fresh independent complete-delta review; fix actionable findings and rerun affected checks.
- [ ] Commit/push/open PR targeting `dotfiles`, recording todo ID, evidence, exact verification and review. Mark done only on completion; keep cockpit-session-doing current.
