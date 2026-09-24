package octoauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type resolveRoundTrip func(*http.Request) (*http.Response, error)

func (f resolveRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func resolverTestConfig(handler http.HandlerFunc) *Config {
	return &Config{
		BaseURL: "http://resolve.test",
		HTTPClient: &http.Client{Transport: resolveRoundTrip(func(r *http.Request) (*http.Response, error) {
			w := httptest.NewRecorder()
			handler(w, r)
			return w.Result(), nil
		})},
	}
}

func resolveFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("../contract/resolve-fixtures.json")
	require.NoError(t, err)
	var fixtures map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &fixtures))
	fixture := fixtures[name]
	require.NotEmpty(t, fixture)
	return fixture
}

func TestResolverRequiresBaseURL(t *testing.T) {
	assert.Panics(t, func() { NewResolver(&Config{}) })
	assert.NotPanics(t, func() { NewResolver(&Config{BaseURL: "http://example.com"}) })
}

func TestResolverOBORequestAndPrincipal(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/internal/auth/resolve", r.URL.Path)
		assert.Equal(t, http.Header{
			"Accept":        []string{"application/json"},
			"Cache-Control": []string{"no-store"},
			"Content-Type":  []string{"application/json"},
		}, r.Header)
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		assert.Equal(t, "bf_secret", body["bot_token"])
		assert.Equal(t, "OBO", body["mode"])
		assert.Equal(t, "space-1", body["space_id"])
		assert.Equal(t, "project.read", body["action"])
		assert.NotContains(t, body, "on_behalf_of")
		_, _ = w.Write(resolveFixture(t, "obo"))
	})
	r := NewResolver(resolverTestConfig(handler))
	p, err := r.Resolve(context.Background(), "bf_secret", ResolveRequest{Mode: ModeOBO, SpaceID: "space-1", Action: "project.read"})
	require.NoError(t, err)
	assert.Equal(t, "bot-1", p.Actor.UID)
	assert.Equal(t, "owner-1", p.Subject.UID)
	assert.Equal(t, "ALL", p.Delegation.MatchedScope)
}

func TestResolverRejectsMissingSpaceWithoutNetwork(t *testing.T) {
	called := false
	r := NewResolver(resolverTestConfig(func(http.ResponseWriter, *http.Request) { called = true }))
	_, err := r.Resolve(context.Background(), "bf_secret", ResolveRequest{Mode: ModeAsBot})
	require.Error(t, err)
	assert.False(t, called)
}

func TestResolverRejectsNonUserBotCredentialsWithoutNetwork(t *testing.T) {
	for _, credential := range []string{
		"session-token",
		"uk_" + "01234567890123456789012345678901",
		"app_reserved",
		"bf_",
	} {
		t.Run(credential, func(t *testing.T) {
			called := false
			r := NewResolver(resolverTestConfig(func(http.ResponseWriter, *http.Request) { called = true }))
			_, err := r.Resolve(context.Background(), credential, ResolveRequest{Mode: ModeAsBot, SpaceID: "S"})
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInvalidCredential))
			assert.False(t, called)
		})
	}
}

func TestResolverMapsWireCodeNotStatusAlone(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write(resolveFixture(t, "delegation_denied"))
	})
	r := NewResolver(resolverTestConfig(handler))
	_, err := r.Resolve(context.Background(), "bf_secret", ResolveRequest{Mode: ModeOBO, SpaceID: "space-1", Action: "project.read"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrForbidden))
	var authErr *Error
	require.ErrorAs(t, err, &authErr)
	assert.Equal(t, "delegation_denied", authErr.Code)
	assert.Equal(t, "request-1", authErr.RequestID)
}

func TestResolverAsBotHasNoDelegation(t *testing.T) {
	r := NewResolver(resolverTestConfig(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]any
		require.NoError(t, json.NewDecoder(req.Body).Decode(&body))
		assert.Equal(t, "AS_BOT", body["mode"])
		assert.NotContains(t, body, "action")
		_, _ = w.Write(resolveFixture(t, "as_bot"))
	}))
	p, err := r.Resolve(context.Background(), "bf_secret", ResolveRequest{Mode: ModeAsBot, SpaceID: "space-1"})
	require.NoError(t, err)
	assert.Equal(t, p.Actor, p.Subject)
	assert.Nil(t, p.Delegation)
}

func TestResolverAsBotNormalizesEmptyAction(t *testing.T) {
	r := NewResolver(resolverTestConfig(func(w http.ResponseWriter, req *http.Request) {
		var body map[string]any
		require.NoError(t, json.NewDecoder(req.Body).Decode(&body))
		assert.NotContains(t, body, "action")
		_, _ = w.Write(resolveFixture(t, "as_bot"))
	}))
	_, err := r.Resolve(context.Background(), "bf_secret", ResolveRequest{Mode: ModeAsBot, SpaceID: "space-1", Action: ""})
	require.NoError(t, err)
}

func TestResolverRejectsRemovedServiceErrorCode(t *testing.T) {
	r := NewResolver(resolverTestConfig(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"untrusted_service","request_id":"R"}`))
	}))
	_, err := r.Resolve(context.Background(), "bf_secret", ResolveRequest{Mode: ModeAsBot, SpaceID: "S"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInfraFailure))
	assert.False(t, errors.Is(err, ErrInvalidCredential))
}

func TestResolverRejectsMismatchedSubject(t *testing.T) {
	r := NewResolver(resolverTestConfig(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"mode":"OBO","actor":{"uid":"bot-1","kind":"BOT","space_id":"S"},"subject":{"uid":"bot-2","kind":"BOT","space_id":"S"}}`))
	}))
	_, err := r.Resolve(context.Background(), "bf_secret", ResolveRequest{Mode: ModeOBO, SpaceID: "S", Action: "project.read"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInfraFailure))
}

func TestResolverRejectsMalformedOBODelegation(t *testing.T) {
	validDecisionID := "0123456789abcdef0123456789abcdef"
	tests := []struct {
		name       string
		delegation string
	}{
		{name: "missing policy version", delegation: `"grant_id":7,"matched_scope":"ALL","action":"project.read","decision_id":"` + validDecisionID + `"`},
		{name: "zero policy version", delegation: `"grant_id":7,"matched_scope":"ALL","policy_version":0,"action":"project.read","decision_id":"` + validDecisionID + `"`},
		{name: "negative policy version", delegation: `"grant_id":7,"matched_scope":"ALL","policy_version":-1,"action":"project.read","decision_id":"` + validDecisionID + `"`},
		{name: "missing decision id", delegation: `"grant_id":7,"matched_scope":"ALL","policy_version":1,"action":"project.read"`},
		{name: "invalid decision id", delegation: `"grant_id":7,"matched_scope":"ALL","policy_version":1,"action":"project.read","decision_id":"not-a-decision-id"`},
		{name: "zero grant id", delegation: `"grant_id":0,"matched_scope":"ALL","policy_version":1,"action":"project.read","decision_id":"` + validDecisionID + `"`},
		{name: "wrong scope", delegation: `"grant_id":7,"matched_scope":"PROJECT","policy_version":1,"action":"project.read","decision_id":"` + validDecisionID + `"`},
		{name: "wrong action", delegation: `"grant_id":7,"matched_scope":"ALL","policy_version":1,"action":"admin.write","decision_id":"` + validDecisionID + `"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := `{"mode":"OBO","actor":{"uid":"bot-1","kind":"BOT","space_id":"S"},` +
				`"subject":{"uid":"owner-1","kind":"HUMAN","space_id":"S"},` +
				`"delegation":{` + tt.delegation + `}}`
			r := NewResolver(resolverTestConfig(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			_, err := r.Resolve(context.Background(), "bf_secret", ResolveRequest{Mode: ModeOBO, SpaceID: "S", Action: "project.read"})
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrInfraFailure))
		})
	}
}

func TestResolverRejectsErrorWithoutRequestID(t *testing.T) {
	r := NewResolver(resolverTestConfig(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"delegation_denied"}`))
	}))
	_, err := r.Resolve(context.Background(), "bf_secret", ResolveRequest{Mode: ModeOBO, SpaceID: "S", Action: "project.read"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInfraFailure))
	assert.False(t, errors.Is(err, ErrForbidden))
}

func TestResolverRejectsOversizedResponse(t *testing.T) {
	r := NewResolver(resolverTestConfig(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, maxVerifyBodyBytes+1))
	}))
	_, err := r.Resolve(context.Background(), "bf_secret", ResolveRequest{Mode: ModeAsBot, SpaceID: "S"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInfraFailure))
}
