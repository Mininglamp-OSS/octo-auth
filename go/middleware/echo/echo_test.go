package echo

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	octoauth "github.com/Mininglamp-OSS/octo-auth/go"
)

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

func newSessionApp(opts Options) (*echo.Echo, *captured) {
	cap := &captured{}
	e := echo.New()
	e.Use(New(opts))
	e.GET("/hello", func(c echo.Context) error {
		cap.set(Principal(c))
		return c.String(http.StatusOK, "ok")
	})
	return e, cap
}

type captured struct {
	last *octoauth.Principal
}

func (c *captured) set(p *octoauth.Principal) { c.last = p }

func doGET(e *echo.Echo, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)
	return w
}

func TestEchoHappyPath(t *testing.T) {
	stub := &stubVerifier{
		kind:      octoauth.KindSession,
		principal: &octoauth.Principal{Kind: octoauth.KindSession, UID: "u-1"},
	}
	e, cap := newSessionApp(Options{Verifier: stub})
	w := doGET(e, map[string]string{"token": "tok"})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "u-1", cap.last.UID)
}

func TestEchoRequireKindMismatch(t *testing.T) {
	stub := &stubVerifier{
		kind:      octoauth.KindSession,
		principal: &octoauth.Principal{Kind: octoauth.KindSession, UID: "u-1"},
	}
	e, cap := newSessionApp(Options{Verifier: stub, RequireKind: octoauth.KindAPIKey})
	w := doGET(e, map[string]string{"token": "tok"})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Nil(t, cap.last)
}

func TestEchoVerifyErrorMapping(t *testing.T) {
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
			e, _ := newSessionApp(Options{Verifier: stub})
			w := doGET(e, map[string]string{"token": "tok"})
			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}

func TestEchoMissingCredential(t *testing.T) {
	stub := &stubVerifier{kind: octoauth.KindSession}
	e, _ := newSessionApp(Options{Verifier: stub})
	w := doGET(e, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestEchoSpaceHeaderIncludedPass(t *testing.T) {
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
	e, cap := newSessionApp(Options{Verifier: stub, SpaceHeader: "X-Space-Id"})
	w := doGET(e, map[string]string{"token": "tok", "X-Space-Id": "s-a"})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "s-a", cap.last.SpaceID)
}

func TestEchoSpaceHeaderIncludedReject(t *testing.T) {
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
	e, _ := newSessionApp(Options{Verifier: stub, SpaceHeader: "X-Space-Id"})
	w := doGET(e, map[string]string{"token": "tok", "X-Space-Id": "s-nope"})
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestEchoSpaceHeaderPreV2(t *testing.T) {
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
	e, cap := newSessionApp(Options{Verifier: stub, SpaceHeader: "X-Space-Id"})
	w := doGET(e, map[string]string{"token": "tok", "X-Space-Id": "s-1"})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "s-1", cap.last.SpaceID)
}

func TestEchoCloneIsolation(t *testing.T) {
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
	e := echo.New()
	e.Use(New(Options{Verifier: stub, SpaceHeader: "X-Space-Id"}))
	e.GET("/hello", func(c echo.Context) error {
		p := Principal(c)
		if p1 == nil {
			p1 = p
		} else {
			p2 = p
		}
		return c.String(200, "ok")
	})
	w1 := doGET(e, map[string]string{"token": "tok", "X-Space-Id": "s-a"})
	w2 := doGET(e, map[string]string{"token": "tok", "X-Space-Id": "s-b"})
	require.Equal(t, http.StatusOK, w1.Code)
	require.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "s-a", p1.SpaceID)
	assert.Equal(t, "s-b", p2.SpaceID)
	assert.Empty(t, shared.SpaceID)
}

func TestEchoCustomErrorMapper(t *testing.T) {
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		err:  &octoauth.Error{Kind: octoauth.ErrKindInvalidCredential},
	}
	e, _ := newSessionApp(Options{
		Verifier: stub,
		ErrorMapper: func(err error) (int, []byte) {
			return http.StatusTeapot, []byte(`{"custom":"nope"}`)
		},
	})
	w := doGET(e, map[string]string{"token": "tok"})
	assert.Equal(t, http.StatusTeapot, w.Code)
	assert.Contains(t, w.Body.String(), "custom")
}

func TestEchoPrincipalNilWithoutMiddleware(t *testing.T) {
	e := echo.New()
	e.GET("/hello", func(c echo.Context) error {
		if Principal(c) != nil {
			t.Fatal("Principal must be nil without middleware")
		}
		return c.String(200, "ok")
	})
	w := doGET(e, nil)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestEchoPanicsWithoutVerifier(t *testing.T) {
	assert.Panics(t, func() { New(Options{}) })
}

func TestEchoNoCredentialLeakInErrorBody(t *testing.T) {
	cred := "secret-do-not-echo"
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		err:  &octoauth.Error{Kind: octoauth.ErrKindInvalidCredential, Message: "reason includes " + cred},
	}
	e, _ := newSessionApp(Options{Verifier: stub})
	w := doGET(e, map[string]string{"token": cred})
	assert.NotContains(t, w.Body.String(), cred)
	assert.Equal(t, `{"error":"unauthorized"}`, strings.TrimSpace(w.Body.String()))
}
