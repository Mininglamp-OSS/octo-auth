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

// TestRequireSpaceMemberBotEmptySpaceIDFailClosed pins OctoBoooot's
// round-4 P0 on octo-auth#2: if octo-server returns a contract-violating
// VerifyBotResp with Scope="space" and SpaceID="", the prior revision
// silently fell into the compat-pass branch (RequireSpaceMember had no
// CtxKeyContextIncluded to enforce on), and any X-Space-Id was accepted.
// The fix sets CtxKeyContextIncluded=true with an empty verified-spaces
// list so any non-empty X-Space-Id is denied with 403.
func TestRequireSpaceMemberBotEmptySpaceIDFailClosed(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contract.VerifyBotResp{
			SchemaVersion: 1, Kind: "bot", BotUID: "b1", BotName: "Bot",
			BotKind: "app", Scope: "space", SpaceID: "", // contract violation
			OwnerUID: "u1",
		})
	}))
	defer srv.Close()
	c, _ := New(Options{ServerURL: srv.URL})

	r := gin.New()
	r.Use(c.Middleware(ScopeBot), c.RequireSpaceMember())
	r.GET("/x", func(ctx *gin.Context) { ctx.Status(200) })

	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer app_test_app_bot_token_value_here")
	req.Header.Set("X-Space-Id", "sp_attacker_chose")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("contract-violating Scope=space + empty SpaceID with non-empty X-Space-Id MUST 403 (fail-closed); got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestRequireSpaceMemberAPIKeyBoundSpaceMatchPasses pins Jerry-Xin's
// round-4 P0 on octo-auth#2: an API key bound to a single space with
// no owned bots (verify response: context_included=true, space_id="sp_A",
// owned_bots_by_space={}) MUST pass RequireSpaceMember when the request
// header X-Space-Id matches the bound space. The prior revision built
// verified-spaces from OwnedBotsBySpace keys only, producing an empty
// list — and 403ing every legitimate caller of an unbound-bot API key.
func TestRequireSpaceMemberAPIKeyBoundSpaceMatchPasses(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contract.VerifyAPIKeyResp{
			SchemaVersion: 1, Kind: "apikey",
			UID:             "u_owner",
			KeyID:           "k1",
			SpaceID:         "sp_A",
			ContextIncluded: true,
			// OwnedBotsBySpace deliberately empty: the legitimate
			// "API key bound to single space, no owned bots" shape.
		})
	}))
	defer srv.Close()
	c, _ := New(Options{ServerURL: srv.URL})

	r := gin.New()
	r.Use(c.Middleware(ScopeDaemon), c.RequireSpaceMember())
	r.GET("/x", func(ctx *gin.Context) { ctx.Status(200) })

	req := httptest.NewRequest("GET", "/x", nil)
	apiKey := "uk_" + "k1234567890123456789012345678901"
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("X-Space-Id", "sp_A")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("API key bound to sp_A with matching X-Space-Id MUST pass; got %d (body: %s)", w.Code, w.Body.String())
	}
}

// TestRequireSpaceMemberAPIKeyBoundSpaceMismatchFailsClosed is the
// negative-control complement: API key bound to sp_A with
// X-Space-Id=sp_B (and no owned bots in sp_B) MUST 403.
func TestRequireSpaceMemberAPIKeyBoundSpaceMismatchFailsClosed(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(contract.VerifyAPIKeyResp{
			SchemaVersion: 1, Kind: "apikey",
			UID: "u_owner", KeyID: "k1",
			SpaceID: "sp_A", ContextIncluded: true,
		})
	}))
	defer srv.Close()
	c, _ := New(Options{ServerURL: srv.URL})

	r := gin.New()
	r.Use(c.Middleware(ScopeDaemon), c.RequireSpaceMember())
	r.GET("/x", func(ctx *gin.Context) { ctx.Status(200) })

	req := httptest.NewRequest("GET", "/x", nil)
	apiKey := "uk_" + "k1234567890123456789012345678901"
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("X-Space-Id", "sp_B")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("API key bound to sp_A with non-matching X-Space-Id sp_B MUST 403; got %d (body: %s)", w.Code, w.Body.String())
	}
}
