package nethttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

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

type captured struct {
	last *octoauth.Principal
}

func (c *captured) set(p *octoauth.Principal) { c.last = p }

func newSessionHandler(opts Options) (http.Handler, *captured) {
	cap := &captured{}
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cap.set(Principal(r.Context()))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	return Wrap(inner, opts), cap
}

func doGET(h http.Handler, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/hello", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestNetHTTPHappyPath(t *testing.T) {
	stub := &stubVerifier{
		kind:      octoauth.KindSession,
		principal: &octoauth.Principal{Kind: octoauth.KindSession, UID: "u-1"},
	}
	h, cap := newSessionHandler(Options{Verifier: stub})
	w := doGET(h, map[string]string{"token": "tok"})
	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, cap.last)
	assert.Equal(t, "u-1", cap.last.UID)
}

func TestNetHTTPRequireKindMismatch(t *testing.T) {
	stub := &stubVerifier{
		kind:      octoauth.KindSession,
		principal: &octoauth.Principal{Kind: octoauth.KindSession, UID: "u-1"},
	}
	h, cap := newSessionHandler(Options{Verifier: stub, RequireKind: octoauth.KindAPIKey})
	w := doGET(h, map[string]string{"token": "tok"})
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Nil(t, cap.last)
	assert.Zero(t, stub.calls.Load())
}

func TestNetHTTPErrorMapping(t *testing.T) {
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
			h, _ := newSessionHandler(Options{Verifier: stub})
			w := doGET(h, map[string]string{"token": "tok"})
			assert.Equal(t, tc.wantStatus, w.Code)
			assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
		})
	}
}

func TestNetHTTPMissingCredential(t *testing.T) {
	stub := &stubVerifier{kind: octoauth.KindSession}
	h, _ := newSessionHandler(Options{Verifier: stub})
	w := doGET(h, nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestNetHTTPSpaceHeaderIncludedPass(t *testing.T) {
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
	h, cap := newSessionHandler(Options{Verifier: stub, SpaceHeader: "X-Space-Id"})
	w := doGET(h, map[string]string{"token": "tok", "X-Space-Id": "s-a"})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "s-a", cap.last.SpaceID)
}

func TestNetHTTPSpaceHeaderIncludedReject(t *testing.T) {
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
	h, _ := newSessionHandler(Options{Verifier: stub, SpaceHeader: "X-Space-Id"})
	w := doGET(h, map[string]string{"token": "tok", "X-Space-Id": "s-nope"})
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestNetHTTPSpaceHeaderPreV2(t *testing.T) {
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		principal: &octoauth.Principal{
			Kind:    octoauth.KindSession,
			UID:     "u-1",
			Context: octoauth.PrincipalContext{Kind: octoauth.ContextNotIncluded},
		},
	}
	h, cap := newSessionHandler(Options{Verifier: stub, SpaceHeader: "X-Space-Id"})
	w := doGET(h, map[string]string{"token": "tok", "X-Space-Id": "s-1"})
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "s-1", cap.last.SpaceID)
}

func TestNetHTTPCloneIsolation(t *testing.T) {
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
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := Principal(r.Context())
		if p1 == nil {
			p1 = p
		} else {
			p2 = p
		}
		w.WriteHeader(http.StatusOK)
	})
	h := Wrap(inner, Options{Verifier: stub, SpaceHeader: "X-Space-Id"})

	w1 := doGET(h, map[string]string{"token": "tok", "X-Space-Id": "s-a"})
	w2 := doGET(h, map[string]string{"token": "tok", "X-Space-Id": "s-b"})
	require.Equal(t, http.StatusOK, w1.Code)
	require.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "s-a", p1.SpaceID)
	assert.Equal(t, "s-b", p2.SpaceID)
	assert.Empty(t, shared.SpaceID)
}

func TestNetHTTPCustomErrorMapper(t *testing.T) {
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		err:  &octoauth.Error{Kind: octoauth.ErrKindInvalidCredential},
	}
	h, _ := newSessionHandler(Options{
		Verifier: stub,
		ErrorMapper: func(err error) (int, []byte) {
			return http.StatusTeapot, []byte(`{"custom":"nope"}`)
		},
	})
	w := doGET(h, map[string]string{"token": "tok"})
	assert.Equal(t, http.StatusTeapot, w.Code)
	assert.Contains(t, w.Body.String(), "custom")
}

func TestNetHTTPPrincipalNilForNilCtx(t *testing.T) {
	assert.Nil(t, Principal(nil))
}

func TestNetHTTPPrincipalNilWithoutMiddleware(t *testing.T) {
	assert.Nil(t, Principal(context.Background()))
}

func TestNetHTTPPanicsWithoutVerifier(t *testing.T) {
	assert.Panics(t, func() {
		Wrap(http.NotFoundHandler(), Options{})
	})
}

func TestNetHTTPNoCredentialLeakInErrorBody(t *testing.T) {
	cred := "supersecret-token"
	stub := &stubVerifier{
		kind: octoauth.KindSession,
		err:  &octoauth.Error{Kind: octoauth.ErrKindInvalidCredential, Message: "reason " + cred},
	}
	h, _ := newSessionHandler(Options{Verifier: stub})
	w := doGET(h, map[string]string{"token": cred})
	assert.NotContains(t, w.Body.String(), cred)
	assert.Equal(t, `{"error":"unauthorized"}`, strings.TrimSpace(w.Body.String()))
}
