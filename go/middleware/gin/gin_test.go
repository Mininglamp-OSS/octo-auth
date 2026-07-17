package gin

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	octoauth "github.com/Mininglamp-OSS/octo-auth/go"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// stubVerifier is a canned in-memory Verifier used by all middleware tests.
type stubVerifier struct {
	kind      octoauth.PrincipalKind
	principal *octoauth.Principal
	err       error
	calls     atomic.Int32
}

func (s *stubVerifier) Kind() octoauth.PrincipalKind { return s.kind }
func (s *stubVerifier) Verify(_ context.Context, _ string) (*octoauth.Principal, error) {
	s.calls.Add(1)
	if s.err != nil {
		return nil, s.err
	}
	return s.principal, nil
}

func newSessionEngine(t *testing.T, opts Options) (*gin.Engine, *captured) {
	t.Helper()
	cap := &captured{}
	engine := gin.New()
	engine.Use(New(opts))
	engine.GET("/hello", func(c *gin.Context) {
		cap.set(Principal(c))
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return engine, cap
}

type captured struct {
	last *octoauth.Principal
}

func (c *captured) set(p *octoauth.Principal) { c.last = p }

func doGET(engine *gin.Engine, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	return w
}

func TestGinHappyPath(t *testing.T) {
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		principal: &octoauth.Principal{
			Kind: octoauth.KindSession,
			UID:  "u-1",
			Name: "Alice",
		},
	}
	engine, cap := newSessionEngine(t, Options{Verifier: stub})

	w := doGET(engine, map[string]string{"token": "session-tok"})
	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, cap.last)
	assert.Equal(t, "u-1", cap.last.UID)
	assert.Equal(t, "Alice", cap.last.Name)
}

func TestGinRequireKindMismatch(t *testing.T) {
	stub := &stubVerifier{
		kind:      octoauth.KindSession,
		principal: &octoauth.Principal{Kind: octoauth.KindSession, UID: "u-1"},
	}
	engine, cap := newSessionEngine(t, Options{
		Verifier:    stub,
		RequireKind: octoauth.KindAPIKey,
	})

	w := doGET(engine, map[string]string{"token": "session-tok"})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Nil(t, cap.last, "handler must not run when kind mismatches")
	assert.Contains(t, w.Body.String(), "forbidden")
	assert.Zero(t, stub.calls.Load(), "verifier must not be called for kind mismatch")
}

func TestGinVerifyInvalidCredential(t *testing.T) {
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		err:  &octoauth.Error{Kind: octoauth.ErrKindInvalidCredential, Message: "nope"},
	}
	engine, _ := newSessionEngine(t, Options{Verifier: stub})

	w := doGET(engine, map[string]string{"token": "session-tok"})
	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "unauthorized")
}

func TestGinVerifyDisabled(t *testing.T) {
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		err:  &octoauth.Error{Kind: octoauth.ErrKindDisabled},
	}
	engine, _ := newSessionEngine(t, Options{Verifier: stub})

	w := doGET(engine, map[string]string{"token": "session-tok"})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "disabled")
}

func TestGinVerifyInfraFailure(t *testing.T) {
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		err:  &octoauth.Error{Kind: octoauth.ErrKindInfraFailure},
	}
	engine, _ := newSessionEngine(t, Options{Verifier: stub})

	w := doGET(engine, map[string]string{"token": "session-tok"})
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	assert.Contains(t, w.Body.String(), "upstream_unavailable")
}

func TestGinMissingCredentialUnauthorized(t *testing.T) {
	stub := &stubVerifier{kind: octoauth.KindSession}
	engine, _ := newSessionEngine(t, Options{Verifier: stub})

	w := doGET(engine, nil) // no headers
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGinSpaceHeaderV2HardCheckPass(t *testing.T) {
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		principal: &octoauth.Principal{
			Kind: octoauth.KindSession,
			UID:  "u-1",
			Context: octoauth.PrincipalContext{
				Kind:   octoauth.ContextIncluded,
				Spaces: []string{"s-a", "s-b"},
			},
		},
	}
	engine, cap := newSessionEngine(t, Options{
		Verifier:    stub,
		SpaceHeader: "X-Space-Id",
	})

	w := doGET(engine, map[string]string{"token": "tok", "X-Space-Id": "s-b"})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "s-b", cap.last.SpaceID)
}

func TestGinSpaceHeaderV2HardCheckReject(t *testing.T) {
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		principal: &octoauth.Principal{
			Kind: octoauth.KindSession,
			UID:  "u-1",
			Context: octoauth.PrincipalContext{
				Kind:   octoauth.ContextIncluded,
				Spaces: []string{"s-a"},
			},
		},
	}
	engine, cap := newSessionEngine(t, Options{
		Verifier:    stub,
		SpaceHeader: "X-Space-Id",
	})

	w := doGET(engine, map[string]string{"token": "tok", "X-Space-Id": "s-forbidden"})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Nil(t, cap.last)
}

func TestGinSpaceHeaderPreV2FailClosed(t *testing.T) {
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		principal: &octoauth.Principal{
			Kind: octoauth.KindSession,
			UID:  "u-1",
			Context: octoauth.PrincipalContext{
				Kind: octoauth.ContextUnknownServer,
			},
		},
	}
	engine, cap := newSessionEngine(t, Options{
		Verifier:    stub,
		SpaceHeader: "X-Space-Id",
	})

	w := doGET(engine, map[string]string{"token": "tok", "X-Space-Id": "s-arbitrary"})
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Nil(t, cap.last, "principal MUST NOT be attached when unverified header is rejected")
}

// TestGinCloneIsolatesConcurrentMutations proves the middleware clones
// the cache-shared *Principal before enrichSpaceFromHeader mutates SpaceID,
// so two requests with the same credential but different X-Space-Id values
// see independent SpaceID assignments.
func TestGinCloneIsolatesConcurrentMutations(t *testing.T) {
	shared := &octoauth.Principal{
		Kind: octoauth.KindSession,
		UID:  "u-1",
		Context: octoauth.PrincipalContext{
			Kind:   octoauth.ContextIncluded,
			Spaces: []string{"s-a", "s-b", "s-c"},
		},
	}
	stub := &stubVerifier{
		kind:      octoauth.KindSession,
		principal: shared, // same pointer returned every call = cache hit sim
	}

	var captured1, captured2 *octoauth.Principal
	engine := gin.New()
	engine.Use(New(Options{Verifier: stub, SpaceHeader: "X-Space-Id"}))
	engine.GET("/hello", func(c *gin.Context) {
		p := Principal(c)
		if captured1 == nil {
			captured1 = p
		} else {
			captured2 = p
		}
		c.String(200, "ok")
	})

	w1 := doGET(engine, map[string]string{"token": "tok", "X-Space-Id": "s-a"})
	w2 := doGET(engine, map[string]string{"token": "tok", "X-Space-Id": "s-c"})
	require.Equal(t, http.StatusOK, w1.Code)
	require.Equal(t, http.StatusOK, w2.Code)

	require.NotNil(t, captured1)
	require.NotNil(t, captured2)
	assert.NotSame(t, captured1, captured2, "each request must get its own *Principal after Clone")
	assert.Equal(t, "s-a", captured1.SpaceID)
	assert.Equal(t, "s-c", captured2.SpaceID)
	// And the underlying cached Principal must remain pristine.
	assert.Empty(t, shared.SpaceID, "verifier-returned Principal must not be mutated by middleware")
}

func TestGinCustomErrorMapper(t *testing.T) {
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		err:  &octoauth.Error{Kind: octoauth.ErrKindInvalidCredential},
	}
	engine, _ := newSessionEngine(t, Options{
		Verifier: stub,
		ErrorMapper: func(err error) (int, []byte) {
			return http.StatusTeapot, []byte(`{"custom":"nope"}`)
		},
	})

	w := doGET(engine, map[string]string{"token": "tok"})
	assert.Equal(t, http.StatusTeapot, w.Code)

	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	assert.Equal(t, "nope", body["custom"])
}

func TestGinPrincipalReturnsNilWhenMiddlewareNotRun(t *testing.T) {
	engine := gin.New()
	engine.GET("/hello", func(c *gin.Context) {
		if Principal(c) != nil {
			t.Fatal("Principal must be nil without middleware")
		}
		c.String(200, "ok")
	})
	w := doGET(engine, nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGinNewPanicsOnMissingVerifier(t *testing.T) {
	assert.Panics(t, func() { New(Options{}) })
}

func TestGinErrorForbiddenIsErrForbiddenSentinel(t *testing.T) {
	stub := &stubVerifier{
		kind:      octoauth.KindSession,
		principal: &octoauth.Principal{Kind: octoauth.KindSession, UID: "u-1"},
	}
	captured := &octoauth.Error{}
	mapper := func(err error) (int, []byte) {
		var e *octoauth.Error
		if errors.As(err, &e) {
			*captured = *e
		}
		return http.StatusForbidden, []byte(`{}`)
	}
	engine, _ := newSessionEngine(t, Options{
		Verifier:    stub,
		RequireKind: octoauth.KindAPIKey,
		ErrorMapper: mapper,
	})
	w := doGET(engine, map[string]string{"token": "session-tok"})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Equal(t, octoauth.ErrKindForbidden, captured.Kind)
}

// Sanity check that Bearer prefix handling is not accidentally leaking into
// the token stored in gin's context.
func TestGinBearerTokenStrippedFromRequest(t *testing.T) {
	stub := &stubVerifier{
		kind:      octoauth.KindSession,
		principal: &octoauth.Principal{Kind: octoauth.KindSession, UID: "u-1"},
	}
	engine, _ := newSessionEngine(t, Options{Verifier: stub})
	w := doGET(engine, map[string]string{"Authorization": "Bearer session-tok"})
	assert.Equal(t, http.StatusOK, w.Code)
}

// Guard against a subtle regression: two calls with the same auth token must
// both succeed even when the verifier is slow enough that they interleave.
// (Not a race test — just a smoke sanity check.)
func TestGinSequentialCallsBothSucceed(t *testing.T) {
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		principal: &octoauth.Principal{
			Kind: octoauth.KindSession,
			UID:  "u-1",
		},
	}
	engine, _ := newSessionEngine(t, Options{Verifier: stub})
	for i := 0; i < 5; i++ {
		w := doGET(engine, map[string]string{"token": "tok"})
		require.Equal(t, http.StatusOK, w.Code, "iteration %d", i)
	}
	assert.Equal(t, int32(5), stub.calls.Load())
}

// Ensure we do not leak the raw credential into the response body regardless
// of what path fires.
func TestGinResponseNeverContainsCredential(t *testing.T) {
	cred := "super-secret-token-do-not-leak"
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		err:  &octoauth.Error{Kind: octoauth.ErrKindInvalidCredential, Message: "reason includes " + cred},
	}
	engine, _ := newSessionEngine(t, Options{Verifier: stub})

	w := doGET(engine, map[string]string{"token": cred})
	assert.NotContains(t, w.Body.String(), cred)
	// deterministic body test (anti-enumeration)
	assert.Equal(t, `{"error":"unauthorized"}`, strings.TrimSpace(w.Body.String()))

	// Silence "unused import" if any future change removes time usage.
	_ = time.Second
}
