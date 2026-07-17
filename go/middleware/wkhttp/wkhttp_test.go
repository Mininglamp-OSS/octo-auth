package wkhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	wkhttppkg "github.com/WuKongIM/WuKongIM/pkg/wkhttp"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	octoauth "github.com/Mininglamp-OSS/octo-auth/go"
)

func init() {
	gin.SetMode(gin.TestMode)
}

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

type captured struct {
	last *octoauth.Principal
}

func (c *captured) set(p *octoauth.Principal) { c.last = p }

func newSessionApp(opts Options) (*wkhttppkg.WKHttp, *captured) {
	cap := &captured{}
	app := wkhttppkg.New()
	app.Use(New(opts))
	app.GET("/hello", func(c *wkhttppkg.Context) {
		cap.set(Principal(c))
		c.String(http.StatusOK, "ok")
	})
	return app, cap
}

func doGET(app *wkhttppkg.WKHttp, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	app.ServeHTTP(w, req)
	return w
}

func TestWkHTTPHappyPath(t *testing.T) {
	stub := &stubVerifier{
		kind:      octoauth.KindSession,
		principal: &octoauth.Principal{Kind: octoauth.KindSession, UID: "u-1"},
	}
	app, cap := newSessionApp(Options{Verifier: stub})
	w := doGET(app, map[string]string{"token": "tok"})
	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, cap.last)
	assert.Equal(t, "u-1", cap.last.UID)
}

func TestWkHTTPRequireKindMismatch(t *testing.T) {
	stub := &stubVerifier{
		kind:      octoauth.KindSession,
		principal: &octoauth.Principal{Kind: octoauth.KindSession, UID: "u-1"},
	}
	app, cap := newSessionApp(Options{Verifier: stub, RequireKind: octoauth.KindAPIKey})
	w := doGET(app, map[string]string{"token": "tok"})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Nil(t, cap.last)
}

func TestWkHTTPErrorMapping(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{"invalid", &octoauth.Error{Kind: octoauth.ErrKindInvalidCredential}, http.StatusUnauthorized},
		{"disabled", &octoauth.Error{Kind: octoauth.ErrKindDisabled}, http.StatusForbidden},
		{"infra", &octoauth.Error{Kind: octoauth.ErrKindInfraFailure}, http.StatusServiceUnavailable},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubVerifier{kind: octoauth.KindSession, err: tc.err}
			app, _ := newSessionApp(Options{Verifier: stub})
			w := doGET(app, map[string]string{"token": "tok"})
			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}

func TestWkHTTPMissingCredential(t *testing.T) {
	stub := &stubVerifier{kind: octoauth.KindSession}
	app, _ := newSessionApp(Options{Verifier: stub})
	w := doGET(app, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestWkHTTPSpaceHeaderIncludedPass(t *testing.T) {
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
	app, cap := newSessionApp(Options{Verifier: stub, SpaceHeader: "X-Space-Id"})
	w := doGET(app, map[string]string{"token": "tok", "X-Space-Id": "s-a"})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "s-a", cap.last.SpaceID)
}

func TestWkHTTPSpaceHeaderIncludedReject(t *testing.T) {
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
	app, _ := newSessionApp(Options{Verifier: stub, SpaceHeader: "X-Space-Id"})
	w := doGET(app, map[string]string{"token": "tok", "X-Space-Id": "s-nope"})
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestWkHTTPSpaceHeaderPreV2FailClosed(t *testing.T) {
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		principal: &octoauth.Principal{
			Kind:    octoauth.KindSession,
			UID:     "u-1",
			Context: octoauth.PrincipalContext{Kind: octoauth.ContextUnknownServer},
		},
	}
	app, cap := newSessionApp(Options{Verifier: stub, SpaceHeader: "X-Space-Id"})
	w := doGET(app, map[string]string{"token": "tok", "X-Space-Id": "s-1"})
	require.Equal(t, http.StatusForbidden, w.Code)
	assert.Nil(t, cap.last, "principal MUST NOT be attached when unverified header is rejected")
}

func TestWkHTTPCloneIsolation(t *testing.T) {
	shared := &octoauth.Principal{
		Kind: octoauth.KindSession,
		UID:  "u-1",
		Context: octoauth.PrincipalContext{
			Kind:   octoauth.ContextIncluded,
			Spaces: []string{"s-a", "s-b"},
		},
	}
	stub := &stubVerifier{kind: octoauth.KindSession, principal: shared}

	var p1, p2 *octoauth.Principal
	app := wkhttppkg.New()
	app.Use(New(Options{Verifier: stub, SpaceHeader: "X-Space-Id"}))
	app.GET("/hello", func(c *wkhttppkg.Context) {
		p := Principal(c)
		if p1 == nil {
			p1 = p
		} else {
			p2 = p
		}
		c.String(200, "ok")
	})

	w1 := doGET(app, map[string]string{"token": "tok", "X-Space-Id": "s-a"})
	w2 := doGET(app, map[string]string{"token": "tok", "X-Space-Id": "s-b"})
	require.Equal(t, http.StatusOK, w1.Code)
	require.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "s-a", p1.SpaceID)
	assert.Equal(t, "s-b", p2.SpaceID)
	assert.Empty(t, shared.SpaceID)
}

func TestWkHTTPCustomErrorMapper(t *testing.T) {
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		err:  &octoauth.Error{Kind: octoauth.ErrKindInvalidCredential},
	}
	app, _ := newSessionApp(Options{
		Verifier: stub,
		ErrorMapper: func(err error) (int, []byte) {
			return http.StatusTeapot, []byte(`{"custom":"nope"}`)
		},
	})
	w := doGET(app, map[string]string{"token": "tok"})
	assert.Equal(t, http.StatusTeapot, w.Code)
	assert.Contains(t, w.Body.String(), "custom")
}

func TestWkHTTPPrincipalNilWithoutMiddleware(t *testing.T) {
	app := wkhttppkg.New()
	app.GET("/hello", func(c *wkhttppkg.Context) {
		if Principal(c) != nil {
			t.Fatal("Principal must be nil without middleware")
		}
		c.String(200, "ok")
	})
	w := doGET(app, nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWkHTTPPanicsWithoutVerifier(t *testing.T) {
	assert.Panics(t, func() { New(Options{}) })
}

func TestWkHTTPNoCredentialLeakInErrorBody(t *testing.T) {
	cred := "supersecret"
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		err:  &octoauth.Error{Kind: octoauth.ErrKindInvalidCredential, Message: "reason " + cred},
	}
	app, _ := newSessionApp(Options{Verifier: stub})
	w := doGET(app, map[string]string{"token": cred})
	assert.NotContains(t, w.Body.String(), cred)
	assert.Equal(t, `{"error":"unauthorized"}`, strings.TrimSpace(w.Body.String()))
}
