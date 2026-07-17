package octoauth

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/Mininglamp-OSS/octo-auth/go/internal/testhelpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validAPIKey() string {
	return "uk_" + strings.Repeat("k", 32)
}

func TestUserKeyVerifierHappyPathContextIncluded(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify-api-key", http.StatusOK, `{
		"uid": "u-1",
		"space_id": "s-primary",
		"context_included": true,
		"owned_bots": {"s-primary": ["b-1"], "s-other": ["b-2","b-3"]}
	}`)
	cfg := testConfig(ms.URL())
	v := NewUserKeyVerifier(cfg)

	p, err := v.Verify(context.Background(), validAPIKey())
	require.NoError(t, err)
	assert.Equal(t, KindAPIKey, p.Kind)
	assert.Equal(t, "u-1", p.UID)
	assert.Equal(t, "s-primary", p.SpaceID)
	assert.Empty(t, p.Name, "api-key principals must not carry Name")
	assert.Empty(t, p.Role, "api-key principals must not carry Role")
	assert.Nil(t, p.RelatedUIDs)
	assert.Equal(t, ContextIncluded, p.Context.Kind)
	assert.Equal(t, []string{"s-other", "s-primary"}, p.Context.Spaces,
		"Spaces must be sorted keys of owned_bots for determinism")
	assert.Len(t, p.Context.OwnedBotsBySpace, 2)

	reqs := ms.Requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, "include=context", reqs[0].Query)
	assert.Contains(t, string(reqs[0].Body), `"api_key":"uk_`)
}

func TestUserKeyVerifierContextUnknownServer(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify-api-key", http.StatusOK,
		`{"uid":"u-1","space_id":"s-1"}`)
	cfg := testConfig(ms.URL())
	v := NewUserKeyVerifier(cfg)

	p, err := v.Verify(context.Background(), validAPIKey())
	require.NoError(t, err)
	assert.Equal(t, ContextUnknownServer, p.Context.Kind)
}

func TestUserKeyVerifierContextNotIncluded(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify-api-key", http.StatusOK,
		`{"uid":"u-1","space_id":"s-1","context_included":false}`)
	cfg := testConfig(ms.URL())
	v := NewUserKeyVerifier(cfg)

	p, err := v.Verify(context.Background(), validAPIKey())
	require.NoError(t, err)
	assert.Equal(t, ContextNotIncluded, p.Context.Kind)
}

func TestUserKeyVerifierTooShortShortCircuit(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	cfg := testConfig(ms.URL())
	v := NewUserKeyVerifier(cfg)

	_, err := v.Verify(context.Background(), "uk_short")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredential)
	assert.Empty(t, ms.Requests(), "too-short key MUST NOT hit the network")
}

func TestUserKeyVerifierEmptyShortCircuit(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	cfg := testConfig(ms.URL())
	v := NewUserKeyVerifier(cfg)

	_, err := v.Verify(context.Background(), "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredential)
	assert.Empty(t, ms.Requests())
}

func TestUserKeyVerifier401(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify-api-key", http.StatusUnauthorized, `{"error":"nope"}`)
	cfg := testConfig(ms.URL())
	v := NewUserKeyVerifier(cfg)

	_, err := v.Verify(context.Background(), validAPIKey())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredential)
}

func TestUserKeyVerifier403(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify-api-key", http.StatusForbidden, `{"error":"disabled"}`)
	cfg := testConfig(ms.URL())
	v := NewUserKeyVerifier(cfg)

	_, err := v.Verify(context.Background(), validAPIKey())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDisabled)
}

func TestUserKeyVerifierMissingUIDRejected(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify-api-key", http.StatusOK, `{"space_id":"s-1"}`)
	cfg := testConfig(ms.URL())
	v := NewUserKeyVerifier(cfg)

	_, err := v.Verify(context.Background(), validAPIKey())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredential)
}

func TestUserKeyVerifierMissingSpaceIDRejected(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify-api-key", http.StatusOK, `{"uid":"u-1"}`)
	cfg := testConfig(ms.URL())
	v := NewUserKeyVerifier(cfg)

	_, err := v.Verify(context.Background(), validAPIKey())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredential)
}

func TestUserKeyVerifierCachePositive(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify-api-key", http.StatusOK,
		`{"uid":"u-1","space_id":"s-1","context_included":true}`)
	cfg := testConfig(ms.URL())
	v := NewUserKeyVerifier(cfg)

	tok := validAPIKey()
	first, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)
	second, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)

	assert.NotSame(t, first, second, "Verify must return a defensive clone per call")
	assert.Equal(t, first, second, "clones must be value-equal")
	assert.Len(t, ms.Requests(), 1)

	posKey := "k:" + HashCacheKey(tok)
	val, ok := cfg.Cache.Get(context.Background(), posKey)
	require.True(t, ok)
	require.NotNil(t, val)
}

func TestUserKeyVerifierIncludeContextDisabled(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify-api-key", http.StatusOK,
		`{"uid":"u-1","space_id":"s-1"}`)
	cfg := testConfig(ms.URL())
	cfg.RequestIncludeContext = Ptr(false)
	v := NewUserKeyVerifier(cfg)

	p, err := v.Verify(context.Background(), validAPIKey())
	require.NoError(t, err)
	assert.Equal(t, ContextNotRequested, p.Context.Kind)

	reqs := ms.Requests()
	require.Len(t, reqs, 1)
	assert.Empty(t, reqs[0].Query)
}

func TestSpacesFromOwnedBots(t *testing.T) {
	assert.Nil(t, spacesFromOwnedBots(nil))
	assert.Nil(t, spacesFromOwnedBots(map[string][]string{}))
	assert.Equal(t, []string{"a", "b", "c"},
		spacesFromOwnedBots(map[string][]string{"c": nil, "a": nil, "b": nil}))
}
