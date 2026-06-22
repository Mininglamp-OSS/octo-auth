package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/Mininglamp-OSS/octo-auth/sdk-go/contract"
)

func init() { gin.SetMode(gin.TestMode) }

func TestExtractTokenBearer(t *testing.T) {
	t.Parallel()
	r := gin.New()
	called := false
	r.GET("/x", func(c *gin.Context) {
		tok, kind, ok := extractToken(c)
		if !ok || tok != "abc" || kind != AuthKindSession {
			t.Errorf("got tok=%q kind=%v ok=%v", tok, kind, ok)
		}
		called = true
		c.Status(200)
	})
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer abc")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if !called {
		t.Fatal("handler not reached")
	}
}

func TestExtractTokenLegacyHeader(t *testing.T) {
	// Pins the permanent-invariant fallback documented in §14.3:
	// octo-web / iOS / Android send `token: <raw>` not Bearer; SDK
	// must keep tolerating it.
	t.Parallel()
	r := gin.New()
	r.GET("/x", func(c *gin.Context) {
		tok, kind, ok := extractToken(c)
		if !ok || tok != "raw-session-token" || kind != AuthKindSession {
			t.Errorf("legacy header: tok=%q kind=%v ok=%v", tok, kind, ok)
		}
		c.Status(200)
	})
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("token", "raw-session-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestMiddlewareKindMismatch(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contract.VerifyUserResp{
			SchemaVersion: 1, Kind: "user", UID: "u1",
		})
	}))
	defer srv.Close()
	c, _ := New(Options{ServerURL: srv.URL})

	r := gin.New()
	r.Use(c.Middleware(ScopeDaemon)) // daemon route — only uk_ tokens
	r.GET("/x", func(c *gin.Context) { c.Status(200) })

	// Send a session token to a daemon-only route → 403 KIND_MISMATCH.
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer session-token-not-uk")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", w.Code)
	}
	var env contract.ErrorEnvelope
	_ = json.Unmarshal(w.Body.Bytes(), &env)
	if env.Error.Code != CodeKindMismatch {
		t.Fatalf("code=%q want %q", env.Error.Code, CodeKindMismatch)
	}
}

func TestMiddlewareInjectsContext(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contract.VerifyUserResp{
			SchemaVersion:    1,
			Kind:             "user",
			UID:              "u1",
			Name:             "alice",
			Role:             "admin",
			OwnedBots:        []contract.OwnedBot{{UID: "b1"}, {UID: "b2"}},
			ContextIncluded:  true,
			Spaces:           []string{"sp_a", "sp_b"},
			OwnedBotsBySpace: map[string][]string{"sp_a": {"b1"}, "sp_b": {"b2"}},
		})
	}))
	defer srv.Close()
	c, _ := New(Options{ServerURL: srv.URL})

	r := gin.New()
	r.Use(c.Middleware(ScopeAny))
	r.GET("/x", func(ctx *gin.Context) {
		if GetLoginUID(ctx) != "u1" {
			t.Errorf("uid=%q", GetLoginUID(ctx))
		}
		if GetAuthKind(ctx) != AuthKindSession {
			t.Errorf("kind=%v", GetAuthKind(ctx))
		}
		if !IsContextIncluded(ctx) {
			t.Error("context_included should be true")
		}
		if len(GetVerifiedSpaces(ctx)) != 2 {
			t.Errorf("spaces=%v", GetVerifiedSpaces(ctx))
		}
		if len(GetRelatedUIDs(ctx)) != 3 { // self + 2 bots
			t.Errorf("related=%v", GetRelatedUIDs(ctx))
		}
		ctx.Status(200)
	})

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer u1-session")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestRequireSpaceMemberFailClosed(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contract.VerifyUserResp{
			SchemaVersion:   1, Kind: "user", UID: "u1",
			ContextIncluded: true,
			Spaces:          []string{"sp_a"},
		})
	}))
	defer srv.Close()
	c, _ := New(Options{ServerURL: srv.URL})

	r := gin.New()
	r.Use(c.Middleware(ScopeAny), c.RequireSpaceMember())
	r.GET("/x", func(ctx *gin.Context) { ctx.Status(200) })

	// Caller is verified in sp_a only; X-Space-Id=sp_b must 403.
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer u1-session")
	req.Header.Set("X-Space-Id", "sp_b")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403 (fail-closed)", w.Code)
	}
}

// Compatibility-mode pass: when verify response did NOT include context
// (pre-v1 octo-server), RequireSpaceMember falls back to log-warn-and-pass
// to keep the rollout window viable.
func TestRequireSpaceMemberCompatPasses(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// ContextIncluded=false (default)
		_ = json.NewEncoder(w).Encode(contract.VerifyUserResp{
			SchemaVersion: 1, Kind: "user", UID: "u1",
		})
	}))
	defer srv.Close()
	c, _ := New(Options{ServerURL: srv.URL})

	r := gin.New()
	r.Use(c.Middleware(ScopeAny), c.RequireSpaceMember())
	r.GET("/x", func(ctx *gin.Context) { ctx.Status(200) })

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer u1-session")
	req.Header.Set("X-Space-Id", "anything")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("compat mode: status=%d want 200", w.Code)
	}
}

// TestRequireSpaceMemberBotFailClosed pins yujiawei's P0 fix on
// octo-auth#2: for space-scoped App Bots, the SDK now treats the
// server-verified SpaceID as the authoritative verified-spaces set and
// fails-closed on a non-matching X-Space-Id. The pre-fix middleware
// silently passed every bot request because VerifyBotResp has no
// ContextIncluded field — IsContextIncluded returned false and
// RequireSpaceMember took the compat branch.
func TestRequireSpaceMemberBotFailClosed(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contract.VerifyBotResp{
			SchemaVersion: 1, Kind: "bot", BotUID: "b1", BotName: "Bot",
			BotKind: "app", Scope: "space", SpaceID: "sp_A",
			OwnerUID: "u1",
		})
	}))
	defer srv.Close()
	c, _ := New(Options{ServerURL: srv.URL})

	r := gin.New()
	r.Use(c.Middleware(ScopeBot), c.RequireSpaceMember())
	r.GET("/x", func(ctx *gin.Context) { ctx.Status(200) })

	// Attack: bot is bound to sp_A; spoof X-Space-Id sp_B.
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer app_test_app_bot_token_value_here")
	req.Header.Set("X-Space-Id", "sp_B")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("bot X-Space-Id forgery must 403; got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestRequireSpaceMemberBotMatchingPasses confirms the positive
// control: when the bot's X-Space-Id matches its binding, the gate
// passes.
func TestRequireSpaceMemberBotMatchingPasses(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contract.VerifyBotResp{
			SchemaVersion: 1, Kind: "bot", BotUID: "b1", BotName: "Bot",
			BotKind: "app", Scope: "space", SpaceID: "sp_A",
			OwnerUID: "u1",
		})
	}))
	defer srv.Close()
	c, _ := New(Options{ServerURL: srv.URL})

	r := gin.New()
	r.Use(c.Middleware(ScopeBot), c.RequireSpaceMember())
	r.GET("/x", func(ctx *gin.Context) {
		if GetSpaceID(ctx) != "sp_A" {
			t.Errorf("space_id leaked to header value; want server binding sp_A")
		}
		ctx.Status(200)
	})

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer app_test_app_bot_token_value_here")
	req.Header.Set("X-Space-Id", "sp_A")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("bot with matching X-Space-Id must pass; got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestBotSpaceBindingNotOverridable pins the second half of
// yujiawei's P0: the X-Space-Id header MUST NOT overwrite the
// server-verified bot binding stored at CtxKeySpaceID.
func TestBotSpaceBindingNotOverridable(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contract.VerifyBotResp{
			SchemaVersion: 1, Kind: "bot", BotUID: "b1", BotName: "Bot",
			BotKind: "app", Scope: "space", SpaceID: "sp_A",
		})
	}))
	defer srv.Close()
	c, _ := New(Options{ServerURL: srv.URL})

	r := gin.New()
	r.Use(c.Middleware(ScopeBot))
	r.GET("/x", func(ctx *gin.Context) {
		if GetSpaceID(ctx) != "sp_A" {
			t.Errorf("space_id was overridden by header: got %q want sp_A", GetSpaceID(ctx))
		}
		ctx.Status(200)
	})

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer app_test_app_bot_token_value_here")
	req.Header.Set("X-Space-Id", "sp_evil")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("middleware should pass (RequireSpaceMember not chained); got %d (body: %s)", w.Code, w.Body.String())
	}
}
