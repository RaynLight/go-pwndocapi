package pwndoc

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func envSuccess(t *testing.T, w http.ResponseWriter, code int, datas any) {
	t.Helper()
	raw, err := json.Marshal(datas)
	if err != nil {
		t.Fatalf("marshal datas: %v", err)
	}
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`{"status":"success","datas":` + string(raw) + `}`))
}

func envError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	b, _ := json.Marshal(msg)
	_, _ = w.Write([]byte(`{"status":"error","datas":` + string(b) + `}`))
}

func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := New(srv.URL)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestLoginSetsTokensAndCookie(t *testing.T) {
	var gotCookie string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/users/token":
			if r.Method != http.MethodPost {
				t.Errorf("login method = %s", r.Method)
			}
			var body map[string]string
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["username"] != "alice" || body["password"] != "pw" {
				t.Errorf("login body = %+v", body)
			}
			if r.Header.Get("Cookie") != "" {
				t.Errorf("login should not send a cookie, got %q", r.Header.Get("Cookie"))
			}
			envSuccess(t, w, 200, map[string]string{"token": "tok123", "refreshToken": "ref123"})
		case "/api/users/me":
			gotCookie = r.Header.Get("Cookie")
			envSuccess(t, w, 200, User{Username: "alice"})
		default:
			http.NotFound(w, r)
		}
	})

	ctx := context.Background()
	if err := c.Login(ctx, "alice", "pw", ""); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !c.IsAuthenticated() {
		t.Fatal("expected authenticated")
	}
	access, refresh := c.Tokens()
	if access != "tok123" || refresh != "ref123" {
		t.Fatalf("tokens = %q / %q", access, refresh)
	}
	if _, err := c.Users.Me(ctx); err != nil {
		t.Fatalf("Me: %v", err)
	}
	if gotCookie != "token=JWT tok123" {
		t.Fatalf("auth cookie = %q, want %q", gotCookie, "token=JWT tok123")
	}
}

func TestAutoRefreshOn401(t *testing.T) {
	var refreshCalls, meCalls int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/users/token":
			envSuccess(t, w, 200, map[string]string{"token": "old", "refreshToken": "r1"})
		case "/api/users/refreshtoken":
			atomic.AddInt32(&refreshCalls, 1)
			if !strings.Contains(r.Header.Get("Cookie"), "refreshToken=r1") {
				t.Errorf("refresh missing refreshToken cookie: %q", r.Header.Get("Cookie"))
			}
			envSuccess(t, w, 200, map[string]string{"token": "new", "refreshToken": "r2"})
		case "/api/users/me":
			atomic.AddInt32(&meCalls, 1)
			if r.Header.Get("Cookie") == "token=JWT old" {
				envError(w, 401, "expired")
				return
			}
			if r.Header.Get("Cookie") != "token=JWT new" {
				t.Errorf("expected refreshed cookie, got %q", r.Header.Get("Cookie"))
			}
			envSuccess(t, w, 200, User{Username: "alice"})
		default:
			http.NotFound(w, r)
		}
	})

	ctx := context.Background()
	if err := c.Login(ctx, "a", "b", ""); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if _, err := c.Users.Me(ctx); err != nil {
		t.Fatalf("Me after refresh: %v", err)
	}
	if refreshCalls != 1 {
		t.Errorf("refreshCalls = %d, want 1", refreshCalls)
	}
	if meCalls != 2 {
		t.Errorf("meCalls = %d, want 2 (401 then retry)", meCalls)
	}
	if acc, _ := c.Tokens(); acc != "new" {
		t.Errorf("access token after refresh = %q, want new", acc)
	}
}

func TestAPIErrorClassification(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		envError(w, 404, "Audit not found")
	})
	_, err := c.Audits.Get(context.Background(), "missing")
	if err == nil {
		t.Fatal("expected error")
	}
	if !IsNotFound(err) {
		t.Errorf("IsNotFound = false for %v", err)
	}
	ae, ok := AsAPIError(err)
	if !ok || ae.Message != "Audit not found" || ae.StatusCode != 404 {
		t.Errorf("APIError = %+v ok=%v", ae, ok)
	}
	if ae.Op != "Audits.Get" {
		t.Errorf("Op = %q, want Audits.Get", ae.Op)
	}
}

func TestRetryOnTransientStatus(t *testing.T) {
	var calls int32
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(503)
			_, _ = io.WriteString(w, `{"status":"error","datas":"busy"}`)
			return
		}
		envSuccess(t, w, 200, []Language{{Locale: "en", Language: "English"}})
	})
	// Tighten backoff so the test is fast.
	c.retryBase = 1
	langs, err := c.Data.Languages(context.Background())
	if err != nil {
		t.Fatalf("Languages: %v", err)
	}
	if len(langs) != 1 || calls != 2 {
		t.Errorf("langs=%d calls=%d, want 1 lang and 2 calls", len(langs), calls)
	}
}

func TestAuditsListQueryParams(t *testing.T) {
	var gotQuery string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		envSuccess(t, w, 200, []AuditSummary{})
	})
	_, err := c.Audits.List(context.Background(), &AuditListFilter{FindingTitle: "xss", Type: "multi"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !strings.Contains(gotQuery, "findingTitle=xss") || !strings.Contains(gotQuery, "type=multi") {
		t.Errorf("query = %q", gotQuery)
	}
}

func TestAuditsCreateParsesNestedAudit(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		envSuccess(t, w, 201, map[string]any{
			"message": "Audit created successfully",
			"audit":   map[string]any{"_id": "aud1", "name": "Test"},
		})
	})
	a, err := c.Audits.Create(context.Background(), CreateAuditParams{Name: "Test", Language: "en", AuditType: "PT"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if a.ID != "aud1" || a.Name != "Test" {
		t.Errorf("audit = %+v", a)
	}
}

func TestFindingsCreateRefetches(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/audits/aud1/findings":
			envSuccess(t, w, 200, "Audit Finding created successfully")
		case r.Method == http.MethodGet && r.URL.Path == "/api/audits/aud1":
			envSuccess(t, w, 200, Audit{ID: "aud1", Findings: []Finding{
				{ID: "f1", Identifier: 1, Title: "XSS"},
			}})
		default:
			http.NotFound(w, r)
		}
	})
	f, err := c.Findings.Create(context.Background(), "aud1", Finding{Title: "XSS"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if f.ID != "f1" || f.Identifier != 1 {
		t.Errorf("finding = %+v", f)
	}
}

func TestAddFindingWithImagesEmbedsCaption(t *testing.T) {
	var createdPOC string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/images/" && r.Method == http.MethodPost:
			envSuccess(t, w, 201, map[string]string{"_id": "img42"})
		case r.URL.Path == "/api/audits/aud1/findings" && r.Method == http.MethodPost:
			var f Finding
			_ = json.NewDecoder(r.Body).Decode(&f)
			createdPOC = f.POC
			envSuccess(t, w, 200, "Audit Finding created successfully")
		case r.URL.Path == "/api/audits/aud1" && r.Method == http.MethodGet:
			envSuccess(t, w, 200, Audit{ID: "aud1", Findings: []Finding{{ID: "f1", Identifier: 1, Title: "Bug", POC: createdPOC}}})
		default:
			http.NotFound(w, r)
		}
	})
	_, err := c.AddFindingWithImages(context.Background(), "aud1",
		Finding{Title: "Bug"},
		FindingImageGroup{Text: "<p>poc</p>", Images: []ImageSpec{{Bytes: []byte{1, 2, 3}, Mime: "image/png", Name: "x.png", Caption: "Fig <1>"}}},
	)
	if err != nil {
		t.Fatalf("AddFindingWithImages: %v", err)
	}
	if !strings.Contains(createdPOC, `<img src="img42" alt="Fig &lt;1&gt;">`) {
		t.Errorf("POC missing escaped captioned img: %q", createdPOC)
	}
	if !strings.Contains(createdPOC, "<p>poc</p>") {
		t.Errorf("POC missing group text: %q", createdPOC)
	}
}

func TestLogoutClearsTokens(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/users/token":
			envSuccess(t, w, 200, map[string]string{"token": "t", "refreshToken": "r"})
		case "/api/users/refreshtoken":
			envSuccess(t, w, 200, "Logged out")
		}
	})
	ctx := context.Background()
	_ = c.Login(ctx, "a", "b", "")
	if err := c.Logout(ctx); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if c.IsAuthenticated() {
		t.Error("expected tokens cleared after logout")
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(""); err == nil {
		t.Error("expected error for empty baseURL")
	}
	if _, err := New("not a url with spaces and no scheme"); err == nil {
		t.Error("expected error for schemeless baseURL")
	}
	if _, err := New("https://x.test", WithHTTPClient(nil)); err == nil {
		t.Error("expected error for nil http client")
	}
}
