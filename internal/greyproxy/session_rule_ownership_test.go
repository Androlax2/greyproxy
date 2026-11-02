package greyproxy

import (
	"path/filepath"
	"reflect"
	"testing"
)

func ownershipSession(t *testing.T, db *DB, id string) {
	t.Helper()
	_, err := CreateOrUpdateSession(db, SessionCreateInput{
		SessionID: id, ContainerName: "codex-agent-cockpit", TTLSeconds: 600,
		NetworkRules: []SessionNetworkRule{
			{DestinationPattern: "github.com", PortPattern: "443"},
			{DestinationPattern: "github.com", PortPattern: "443"},
		},
	}, testEncryptionKey())
	if err != nil {
		t.Fatal(err)
	}
}

func ownershipRules(t *testing.T, db *DB) map[string]Rule {
	t.Helper()
	rules, _, err := GetRules(db, RuleFilter{Destination: "github.com", IncludeExpired: true})
	if err != nil {
		t.Fatal(err)
	}
	byOwner := make(map[string]Rule)
	for _, rule := range rules {
		owner := rule.SessionID.String
		if _, exists := byOwner[owner]; exists {
			t.Errorf("duplicate rule for owner %q", owner)
		}
		byOwner[owner] = rule
	}
	return byOwner
}

func TestSessionRuleOwnership(t *testing.T) {
	for _, globalFirst := range []bool{false, true} {
		name := "sessions_first"
		if globalFirst {
			name = "global_first"
		}
		t.Run(name, func(t *testing.T) {
			db := setupTestDB(t)
			input := RuleCreateInput{ContainerPattern: "codex-agent-cockpit", DestinationPattern: "github.com", PortPattern: "443"}
			if globalFirst {
				if _, err := CreateRule(db, input); err != nil {
					t.Fatal(err)
				}
			}
			ownershipSession(t, db, "first")
			ownershipSession(t, db, "second")
			global, err := CreateRule(db, input)
			if err != nil {
				t.Fatal(err)
			}
			if global.SessionID.Valid {
				t.Errorf("global creation returned a session-owned rule: %+v", global)
			}
			if got := ownershipRules(t, db); len(got) != 3 {
				t.Fatalf("owners = %v, want global, first and second", got)
			}
			first := ownershipRules(t, db)["first"]
			if ok, err := DeleteSession(db, "second"); err != nil || !ok {
				t.Fatalf("delete second: %v, %v", ok, err)
			}
			if got := ownershipRules(t, db); len(got) != 2 || got["first"].ID != first.ID || got[""].ID != global.ID {
				t.Fatalf("deleting second changed another owner: %v", got)
			}
			ownershipSession(t, db, "second")
			if _, err := CreateOrUpdateSession(db, SessionCreateInput{
				SessionID: "first", ContainerName: "codex-agent-cockpit",
			}, testEncryptionKey()); err != nil {
				t.Fatal(err)
			}
			if got := ownershipRules(t, db); len(got) != 2 || got["second"].ID == 0 || got[""].ID != global.ID {
				t.Fatalf("empty upsert changed another owner: %v", got)
			}
		})
	}
}

func TestGlobalRuleOwnership(t *testing.T) {
	for _, method := range []string{"create", "ingest", "allow_pending", "deny_pending", "replace_expired"} {
		t.Run(method, func(t *testing.T) {
			db := setupTestDB(t)
			action := "allow"
			if method == "deny_pending" {
				action = "deny"
			}
			_, err := CreateOrUpdateSession(db, SessionCreateInput{
				SessionID: "owner", ContainerName: "codex-agent-cockpit",
				NetworkRules: []SessionNetworkRule{{DestinationPattern: "github.com", PortPattern: "443", Action: action}},
			}, testEncryptionKey())
			if err != nil {
				t.Fatal(err)
			}
			sessionRule := ownershipRules(t, db)["owner"]
			input := RuleCreateInput{ContainerPattern: "codex-agent-cockpit", DestinationPattern: "github.com", PortPattern: "443", Action: action}
			switch method {
			case "create", "replace_expired":
				if method == "replace_expired" {
					if _, err := db.WriteDB().Exec("UPDATE rules SET expires_at = datetime('now', '-1 minute') WHERE id = ?", sessionRule.ID); err != nil {
						t.Fatal(err)
					}
				}
				_, err = CreateRule(db, input)
			case "ingest":
				var result *IngestResult
				result, err = IngestRules(db, []IngestRuleInput{{ContainerPattern: input.ContainerPattern, DestinationPattern: input.DestinationPattern, PortPattern: input.PortPattern}})
				if err == nil && result.Imported != 1 {
					t.Errorf("imported = %d, want 1", result.Imported)
				}
			default:
				pending, _, createErr := CreateOrUpdatePending(db, "codex-agent-cockpit", "", "github.com", 443, "")
				if createErr != nil {
					t.Fatal(createErr)
				}
				if method == "allow_pending" {
					_, err = AllowPending(db, pending.ID, "exact", "permanent", nil)
				} else {
					_, err = DenyPending(db, pending.ID, "exact", "permanent", nil)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			got := ownershipRules(t, db)
			if len(got) != 2 || got["owner"].ID != sessionRule.ID || got[""].ID == 0 {
				t.Fatalf("global operation must preserve session ownership and create its own rule: %v", got)
			}
			again, err := CreateRule(db, input)
			if err != nil || again == nil || again.ID != got[""].ID {
				t.Fatalf("global deduplication: %v, %v", again, err)
			}
		})
	}
}

// Start with the shipped schema, including its original uniqueness constraint;
// DB.Migrate must upgrade an existing file without losing audit references.
func oldSessionRulesDB(t *testing.T) *DB {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "v16.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.WriteDB().Exec("CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	for i, migration := range migrations[:16] {
		if _, err := db.WriteDB().Exec(migration); err != nil {
			t.Fatalf("old migration %d: %v", i+1, err)
		}
		if _, err := db.WriteDB().Exec("INSERT INTO schema_migrations VALUES (?)", i+1); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func TestSessionRuleMigration(t *testing.T) {
	db := oldSessionRulesDB(t)
	if _, err := CreateOrUpdateSession(db, SessionCreateInput{SessionID: "original", ContainerName: "codex-agent-cockpit", TTLSeconds: 600}, testEncryptionKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.WriteDB().Exec(`INSERT INTO rules (container_pattern, destination_pattern, port_pattern, rule_type, created_by, session_id, expires_at)
 VALUES ('codex-agent-cockpit', 'github.com', '443', 'temporary', 'session:original', 'original', datetime('now', '+600 seconds'))`); err != nil {
		t.Fatal(err)
	}
	original := ownershipRules(t, db)["original"]
	notes := "preserve metadata"
	if _, err := UpdateRule(db, original.ID, RuleUpdateInput{Notes: &notes}); err != nil {
		t.Fatal(err)
	}
	original = ownershipRules(t, db)["original"]
	global, err := CreateRule(db, RuleCreateInput{ContainerPattern: "*", DestinationPattern: "blocked.test", Action: "deny"})
	if err != nil {
		t.Fatal(err)
	}
	log, err := CreateLogEntry(db, LogCreateInput{ContainerName: "codex-agent-cockpit", DestinationHost: "github.com", DestinationPort: 443, Result: "allowed", RuleID: &original.ID})
	if err != nil {
		t.Fatal(err)
	}
	// A deleted high ID must not be reused by a later session's rule.
	if _, err := db.WriteDB().Exec("INSERT INTO rules (id, container_pattern, destination_pattern) VALUES (10000, '*', 'deleted.test'); DELETE FROM rules WHERE id = 10000; PRAGMA foreign_keys = ON;"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := db.Migrate(); err != nil {
			t.Fatalf("migration run %d: %v", i+1, err)
		}
	}
	if got := ownershipRules(t, db)["original"]; !reflect.DeepEqual(got, original) {
		t.Errorf("migration changed stored session rule: got %+v, want %+v", got, original)
	}
	if got, err := GetRule(db, global.ID); err != nil || !reflect.DeepEqual(got, global) {
		t.Errorf("migration changed global rule: %v, %v", got, err)
	}
	var ruleID int64
	if err := db.ReadDB().QueryRow("SELECT rule_id FROM request_logs WHERE id = ?", log.ID).Scan(&ruleID); err != nil || ruleID != original.ID {
		t.Errorf("migration lost audit reference: rule = %d, err = %v", ruleID, err)
	}
	var foreignKeys int
	if err := db.WriteDB().QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		t.Errorf("foreign_keys = %d, err = %v; want restored to 1", foreignKeys, err)
	}
	ownershipSession(t, db, "new")
	if got := ownershipRules(t, db); len(got) != 2 || got["new"].ID <= 10000 {
		t.Errorf("upgraded DB must accept a new owner without reusing old IDs: %v", got)
	}
}

func TestSessionRuleOwnershipFailedUpsert(t *testing.T) {
	db := setupTestDB(t)
	ownershipSession(t, db, "owner")
	original := ownershipRules(t, db)["owner"]
	_, err := CreateOrUpdateSession(db, SessionCreateInput{
		SessionID: "owner", ContainerName: "codex-agent-cockpit", AllowAll: true,
		NetworkRules: []SessionNetworkRule{{DestinationPattern: "invalid.test", Action: "invalid"}},
	}, testEncryptionKey())
	if err == nil {
		t.Error("invalid session rule must fail registration")
	}
	if got := ownershipRules(t, db)["owner"]; !reflect.DeepEqual(got, original) {
		t.Errorf("failed upsert changed existing grants: %v", got)
	}
	session, err := GetSession(db, "owner")
	if err != nil || session.AllowAll {
		t.Errorf("failed upsert changed session: %v, %v", session, err)
	}
}

func testSessionIdentity(t *testing.T, db *DB, name string) *SessionIdentity {
	t.Helper()
	identity, _, accepted, err := CheckClientSecret(db, name, "test-session-secret-0123456789abcdef")
	if err != nil || !accepted || identity == nil {
		t.Fatalf("authenticate session: identity=%v accepted=%v err=%v", identity != nil, accepted, err)
	}
	return identity
}

func TestSessionRuleMigrationRollback(t *testing.T) {
	db := oldSessionRulesDB(t)
	var before string
	if err := db.ReadDB().QueryRow("SELECT sql FROM sqlite_master WHERE name = 'rules'").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if _, err := db.WriteDB().Exec(`PRAGMA foreign_keys = ON;
		CREATE TRIGGER reject_migration BEFORE INSERT ON schema_migrations WHEN NEW.version = 17
		BEGIN SELECT RAISE(ABORT, 'test recording failure'); END;`); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err == nil {
		t.Fatal("expected migration record failure")
	}
	var after string
	if err := db.ReadDB().QueryRow("SELECT sql FROM sqlite_master WHERE name = 'rules'").Scan(&after); err != nil || after != before {
		t.Fatalf("failed migration changed the original table: %q, %v", after, err)
	}
	var version, foreignKeys int
	if err := db.ReadDB().QueryRow("SELECT MAX(version) FROM schema_migrations").Scan(&version); err != nil || version != 16 {
		t.Errorf("version after failure = %d, err = %v", version, err)
	}
	if err := db.WriteDB().QueryRow("PRAGMA foreign_keys").Scan(&foreignKeys); err != nil || foreignKeys != 1 {
		t.Errorf("foreign key setting after failure = %d, err = %v", foreignKeys, err)
	}
	if _, err := db.WriteDB().Exec("DROP TRIGGER reject_migration"); err != nil {
		t.Fatal(err)
	}
	if err := db.Migrate(); err != nil {
		t.Fatalf("retry after rollback: %v", err)
	}
	ownershipSession(t, db, "first")
	ownershipSession(t, db, "second")
	if got := ownershipRules(t, db); len(got) != 2 {
		t.Errorf("ownership after migration retry = %v", got)
	}
}

func TestSessionRuleOwnershipHeartbeatAndCleanup(t *testing.T) {
	db := setupTestDB(t)
	ownershipSession(t, db, "first")
	ownershipSession(t, db, "second")
	global, err := CreateRule(db, RuleCreateInput{ContainerPattern: "codex-agent-cockpit", DestinationPattern: "github.com", PortPattern: "443"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.WriteDB().Exec("UPDATE rules SET expires_at = datetime('now', '+1 minute') WHERE session_id IS NOT NULL"); err != nil {
		t.Fatal(err)
	}
	before := ownershipRules(t, db)
	session, err := HeartbeatSession(db, "first")
	if err != nil || session == nil {
		t.Fatalf("heartbeat: %v, %v", session, err)
	}
	after := ownershipRules(t, db)
	if !after["first"].ExpiresAt.Time.Equal(session.ExpiresAt) || !after["first"].ExpiresAt.Time.After(before["first"].ExpiresAt.Time) {
		t.Error("heartbeat did not extend the owner's rule")
	}
	if !reflect.DeepEqual(before["second"], after["second"]) || after[""].ID != global.ID {
		t.Error("heartbeat changed another owner's rule")
	}
	if _, err := db.WriteDB().Exec("UPDATE sessions SET expires_at = datetime('now', '-1 second') WHERE session_id = 'first'"); err != nil {
		t.Fatal(err)
	}
	if session, err := HeartbeatSession(db, "first"); err != nil || session != nil {
		t.Errorf("expired session revived: %v, %v", session, err)
	}
	ids, err := DeleteExpiredSessions(db)
	if err != nil || !reflect.DeepEqual(ids, []string{"first"}) {
		t.Fatalf("expired cleanup: %v, %v", ids, err)
	}
	after = ownershipRules(t, db)
	if len(after) != 2 || !reflect.DeepEqual(before["second"], after["second"]) || after[""].ID != global.ID {
		t.Errorf("expiry cleanup changed another owner's rule: %v", after)
	}
}
