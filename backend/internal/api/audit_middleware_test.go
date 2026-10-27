package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"aerendil/backend/internal/auth"
	"aerendil/backend/internal/store"
)

func latestAuditForAction(t *testing.T, action string) store.AuditEntry {
	t.Helper()
	entries := dataStore.Audits().List(store.AuditFilter{})
	for _, e := range entries {
		if e.Action == action {
			return e
		}
	}
	t.Fatalf("expected audit entry for action %q, found none in %+v", action, entries)
	return store.AuditEntry{}
}

func TestRedactSensitiveResponseFields(t *testing.T) {
	t.Run("redacts every configured sensitive field in JSON object", func(t *testing.T) {
		orig := sensitiveResponseFields
		sensitiveResponseFields = []string{"clientSecret", "passwordHash", "apiToken"}
		t.Cleanup(func() { sensitiveResponseFields = orig })

		raw := []byte(`{"id":"cred-1","name":"ci","clientSecret":"sec-123","passwordHash":"$2a$10$xyz","apiToken":"tok-abc"}`)
		got := redactSensitiveResponseFields(raw)

		for _, secret := range []string{"sec-123", "$2a$10$xyz", "tok-abc"} {
			if strings.Contains(got, secret) {
				t.Fatalf("expected secret %q to be redacted, got %s", secret, got)
			}
		}

		var parsed map[string]string
		if err := json.Unmarshal([]byte(got), &parsed); err != nil {
			t.Fatalf("unmarshal redacted output: %v", err)
		}
		for _, field := range sensitiveResponseFields {
			if parsed[field] != "[redacted]" {
				t.Fatalf("expected field %q to be [redacted], got %q", field, parsed[field])
			}
		}
		if parsed["id"] != "cred-1" || parsed["name"] != "ci" {
			t.Fatalf("expected non-sensitive fields to remain intact, got %+v", parsed)
		}
	})

	t.Run("returns raw body unchanged when no sensitive fields are present", func(t *testing.T) {
		raw := `{"id":"user-1","username":"alice"}`
		if got := redactSensitiveResponseFields([]byte(raw)); got != raw {
			t.Fatalf("expected unchanged JSON %q, got %q", raw, got)
		}
	})

	t.Run("falls back to raw string when body is not a JSON object", func(t *testing.T) {
		for _, raw := range []string{"not-json", `["array","body"]`, ""} {
			if got := redactSensitiveResponseFields([]byte(raw)); got != raw {
				t.Fatalf("redactSensitiveResponseFields(%q) = %q, want %q", raw, got, raw)
			}
		}
	})
}

func TestWithAuditRedactsSensitiveFieldsInRecordedEntry(t *testing.T) {
	_ = newTestMux(t)

	orig := sensitiveResponseFields
	sensitiveResponseFields = []string{"clientSecret", "passwordHash"}
	t.Cleanup(func() { sensitiveResponseFields = orig })

	action := "credential.create." + store.NewID()
	h := withAudit(auditConfig{
		Action:     action,
		TargetType: "applicationCredential",
	}, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"cred-42","clientSecret":"top-secret-value","passwordHash":"bcrypt-hash-value"}`))
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/application-credentials", strings.NewReader(`{"name":"deploy"}`))
	req = withPrincipal(req, resolvedPrincipal{
		User: &auth.User{ID: "user-admin"},
	})
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "top-secret-value") {
		t.Fatalf("expected client response to still receive the one-time secret, got %s", rec.Body.String())
	}

	entry := latestAuditForAction(t, action)
	if strings.Contains(entry.After, "top-secret-value") || strings.Contains(entry.After, "bcrypt-hash-value") {
		t.Fatalf("expected sensitive fields to be absent from audit entry After, got %s", entry.After)
	}
	if !strings.Contains(entry.After, `"[redacted]"`) {
		t.Fatalf("expected [redacted] marker in audit entry After, got %s", entry.After)
	}
}

func TestAuditRecorder(t *testing.T) {
	t.Run("implicit 200 when handler only calls Write", func(t *testing.T) {
		_ = newTestMux(t)
		action := "recorder.implicit200." + store.NewID()

		h := withAudit(auditConfig{
			Action:     action,
			TargetType: "flag",
		}, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("X-Test", "implicit")
			_, _ = w.Write([]byte(`{"id":"implicit-id"}`))
		})

		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/flags", nil)
		rec := httptest.NewRecorder()
		h(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected implicit 200 status, got %d", rec.Code)
		}
		if rec.Header().Get("X-Test") != "implicit" {
			t.Fatalf("expected header X-Test=implicit, got %q", rec.Header().Get("X-Test"))
		}
		entry := latestAuditForAction(t, action)
		if !entry.Success || entry.StatusCode != http.StatusOK || entry.TargetID != "implicit-id" {
			t.Fatalf("unexpected audit entry for implicit 200: %+v", entry)
		}
	})

	t.Run("implicit 200 when handler calls neither WriteHeader nor Write", func(t *testing.T) {
		_ = newTestMux(t)
		action := "recorder.noop." + store.NewID()

		h := withAudit(auditConfig{
			Action:     action,
			TargetType: "flag",
		}, func(_ http.ResponseWriter, _ *http.Request) {})

		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/flags", nil)
		rec := httptest.NewRecorder()
		h(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected default 200 status when handler writes nothing, got %d", rec.Code)
		}
		entry := latestAuditForAction(t, action)
		if !entry.Success || entry.StatusCode != http.StatusOK {
			t.Fatalf("expected successful 200 audit entry, got %+v", entry)
		}
	})

	t.Run("multiple Write calls concatenate buffered body", func(t *testing.T) {
		_ = newTestMux(t)
		action := "recorder.multiwrite." + store.NewID()

		h := withAudit(auditConfig{
			Action:     action,
			TargetType: "user",
		}, func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"id":`))
			_, _ = w.Write([]byte(`"multi-1",`))
			_, _ = w.Write([]byte(`"username":"alice"}`))
		})

		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/users", nil)
		rec := httptest.NewRecorder()
		h(rec, req)

		wantBody := `{"id":"multi-1","username":"alice"}`
		if rec.Body.String() != wantBody {
			t.Fatalf("expected concatenated body %q, got %q", wantBody, rec.Body.String())
		}
		entry := latestAuditForAction(t, action)
		if entry.After != wantBody || entry.TargetID != "multi-1" {
			t.Fatalf("expected audit entry After=%q and TargetID=multi-1, got %+v", wantBody, entry)
		}
	})

	t.Run("WriteHeader called more than once keeps the first status", func(t *testing.T) {
		_ = newTestMux(t)
		action := "recorder.doubleheader." + store.NewID()

		h := withAudit(auditConfig{
			Action:     action,
			TargetType: "user",
		}, func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusCreated)
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"id":"created-1"}`))
		})

		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/users", nil)
		rec := httptest.NewRecorder()
		h(rec, req)

		if rec.Code != http.StatusCreated {
			t.Fatalf("expected first status 201 to win, got %d", rec.Code)
		}
		entry := latestAuditForAction(t, action)
		if !entry.Success || entry.StatusCode != http.StatusCreated {
			t.Fatalf("expected audit entry to record StatusCode 201 and Success=true, got %+v", entry)
		}
	})
}

func TestTargetIDFrom(t *testing.T) {
	t.Run("ID taken from path value {id}", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/api/users/path-id-99", nil)
		req.SetPathValue("id", "path-id-99")
		if got := targetIDFrom(req, []byte(`{"id":"body-id-ignored"}`)); got != "path-id-99" {
			t.Fatalf("expected path {id} to take precedence, got %q", got)
		}
	})

	t.Run("ID taken from path value {key}", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/flags/feature-x", nil)
		req.SetPathValue("key", "feature-x")
		if got := targetIDFrom(req, []byte(`{"key":"body-key-ignored"}`)); got != "feature-x" {
			t.Fatalf("expected path {key} to take precedence, got %q", got)
		}
	})

	t.Run("ID taken from response body id field", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/users", nil)
		if got := targetIDFrom(req, []byte(`{"id":"body-user-42"}`)); got != "body-user-42" {
			t.Fatalf("expected body id 'body-user-42', got %q", got)
		}
	})

	t.Run("ID taken from response body key field", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/flags", nil)
		if got := targetIDFrom(req, []byte(`{"key":"single-flag-key"}`)); got != "single-flag-key" {
			t.Fatalf("expected body key 'single-flag-key', got %q", got)
		}
	})

	t.Run("ID taken from response body flags array", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/flags", nil)
		if got := targetIDFrom(req, []byte(`{"flags":[{"key":"multi-env-flag"},{"key":"second"}]}`)); got != "multi-env-flag" {
			t.Fatalf("expected first flag key 'multi-env-flag', got %q", got)
		}
	})

	t.Run("returns empty string when no ID is available", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/users", nil)
		for _, body := range [][]byte{
			nil,
			[]byte(""),
			[]byte("not json"),
			[]byte(`{"error":"bad request"}`),
			[]byte(`{"flags":[]}`),
		} {
			if got := targetIDFrom(req, body); got != "" {
				t.Fatalf("targetIDFrom(%q) = %q, want empty string", string(body), got)
			}
		}
	})
}

func TestExtractErrorMessage(t *testing.T) {
	t.Run("extracts error field from JSON error body", func(t *testing.T) {
		body := []byte(`{"error":"username already exists","code":"CF01-0001"}`)
		if got := extractErrorMessage(body); got != "username already exists" {
			t.Fatalf("expected 'username already exists', got %q", got)
		}
	})

	t.Run("falls back to raw body for non-JSON body", func(t *testing.T) {
		body := []byte("upstream gateway timeout")
		if got := extractErrorMessage(body); got != "upstream gateway timeout" {
			t.Fatalf("expected raw non-JSON body, got %q", got)
		}
	})

	t.Run("returns empty string for empty body", func(t *testing.T) {
		if got := extractErrorMessage(nil); got != "" {
			t.Fatalf("expected empty string, got %q", got)
		}
		if got := extractErrorMessage([]byte("")); got != "" {
			t.Fatalf("expected empty string, got %q", got)
		}
	})

	t.Run("falls back to raw body when JSON object has no non-empty error field", func(t *testing.T) {
		body := []byte(`{"detail":"missing error key"}`)
		if got := extractErrorMessage(body); got != string(body) {
			t.Fatalf("expected raw JSON fallback %q, got %q", string(body), got)
		}
	})
}

func TestWithAuditFailedRequests(t *testing.T) {
	_ = newTestMux(t)

	cases := []struct {
		name       string
		status     int
		respBody   string
		wantError  string
		pathID     string
		isService  bool
		actorID    string
		beforeData any
		beforeOK   bool
	}{
		{
			name:      "400 JSON error records failed audit entry with extracted error message",
			status:    http.StatusBadRequest,
			respBody:  `{"error":"invalid request payload","code":"BR01-0001"}`,
			wantError: "invalid request payload",
			actorID:   "user-1",
		},
		{
			name:       "404 JSON error with path targetId and Before state",
			status:     http.StatusNotFound,
			respBody:   `{"error":"user not found","code":"NF01-0001"}`,
			wantError:  "user not found",
			pathID:     "missing-user-id",
			actorID:    "svc-cred-1",
			isService:  true,
			beforeData: map[string]string{"username": "prior"},
			beforeOK:   true,
		},
		{
			name:      "500 plain-text error records failed audit entry with raw body",
			status:    http.StatusInternalServerError,
			respBody:  "unexpected database failure",
			wantError: "unexpected database failure",
			actorID:   "user-2",
		},
		{
			name:      "503 empty error body records failed audit entry with empty error",
			status:    http.StatusServiceUnavailable,
			respBody:  "",
			wantError: "",
			actorID:   "user-3",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			action := "test.failed." + store.NewID()
			var gotDownstreamBody []byte

			h := withAudit(auditConfig{
				Action:     action,
				TargetType: "user",
				Before: func(_ *http.Request, body []byte) (any, bool) {
					return tc.beforeData, tc.beforeOK
				},
			}, func(w http.ResponseWriter, r *http.Request) {
				gotDownstreamBody, _ = io.ReadAll(r.Body)
				w.WriteHeader(tc.status)
				if tc.respBody != "" {
					_, _ = w.Write([]byte(tc.respBody))
				}
			})

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPut, "/api/users/test", strings.NewReader(`{"username":"bob"}`))
			if tc.pathID != "" {
				req.SetPathValue("id", tc.pathID)
			}
			req = withPrincipal(req, resolvedPrincipal{
				User:      &auth.User{ID: tc.actorID},
				IsService: tc.isService,
			})
			rec := httptest.NewRecorder()
			h(rec, req)

			if string(gotDownstreamBody) != `{"username":"bob"}` {
				t.Fatalf("expected handler to read restored request body, got %q", string(gotDownstreamBody))
			}
			if rec.Code != tc.status {
				t.Fatalf("expected status %d, got %d", tc.status, rec.Code)
			}

			entry := latestAuditForAction(t, action)
			if entry.Success {
				t.Fatalf("expected Success=false for status %d, got %+v", tc.status, entry)
			}
			if entry.StatusCode != tc.status {
				t.Fatalf("expected StatusCode=%d, got %d", tc.status, entry.StatusCode)
			}
			if entry.Error != tc.wantError {
				t.Fatalf("expected Error=%q, got %q", tc.wantError, entry.Error)
			}
			if entry.After != "" {
				t.Fatalf("expected empty After on failed request, got %q", entry.After)
			}
			if entry.ActorID != tc.actorID {
				t.Fatalf("expected ActorID=%q, got %q", tc.actorID, entry.ActorID)
			}
			wantActorType := "user"
			if tc.isService {
				wantActorType = "applicationCredential"
			}
			if entry.ActorType != wantActorType {
				t.Fatalf("expected ActorType=%q, got %q", wantActorType, entry.ActorType)
			}
			if tc.pathID != "" && entry.TargetID != tc.pathID {
				t.Fatalf("expected TargetID=%q, got %q", tc.pathID, entry.TargetID)
			}
			if tc.beforeOK && entry.Before == "" {
				t.Fatalf("expected Before to be populated when cfg.Before returns true, got %+v", entry)
			}
		})
	}
}

func TestWithAuditReturns500WhenAppendFails(t *testing.T) {
	_ = newTestMux(t)

	// Open a non-bootstrapped store (not Raft leader) so Audits().Append fails.
	unbootstrapped, err := store.Open(store.Config{
		NodeID:    "follower-node",
		BindAddr:  "127.0.0.1:0",
		DataDir:   t.TempDir(),
		Bootstrap: false,
	})
	if err != nil {
		t.Fatalf("open unbootstrapped store: %v", err)
	}
	t.Cleanup(func() { _ = unbootstrapped.Close() })

	prevStore := dataStore
	dataStore = unbootstrapped
	t.Cleanup(func() { dataStore = prevStore })

	h := withAudit(auditConfig{
		Action:     "user.create",
		TargetType: "user",
	}, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"user-1"}`))
	})

	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/api/users", bytes.NewReader([]byte(`{}`)))
	rec := httptest.NewRecorder()
	h(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 when audit Append fails, got %d: %s", rec.Code, rec.Body.String())
	}
	assertErrorBody(t, rec, CodeInternalAuditFailed)
}
