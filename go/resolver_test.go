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
		BaseURL:      "http://resolve.test",
		ServiceToken: "service-secret",
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

func TestResolverRequiresServiceToken(t *testing.T) {
	assert.Panics(t, func() { NewResolver(&Config{BaseURL: "http://example.com"}) })
}

func TestResolverOBORequestAndPrincipal(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/auth/resolve", r.URL.Path)
		assert.Equal(t, "service-secret", r.Header.Get("X-Octo-Service-Token"))
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

func TestResolverMapsWireCodeNotStatusAlone(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"code":"delegation_denied","request_id":"R"}`))
	})
	r := NewResolver(resolverTestConfig(handler))
	_, err := r.Resolve(context.Background(), "bf_secret", ResolveRequest{Mode: ModeOBO, SpaceID: "space-1", Action: "project.read"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrForbidden))
	var authErr *Error
	require.ErrorAs(t, err, &authErr)
	assert.Equal(t, "delegation_denied", authErr.Code)
	assert.Equal(t, "R", authErr.RequestID)
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

func TestResolverUntrustedServiceIsNotBotCredentialError(t *testing.T) {
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
