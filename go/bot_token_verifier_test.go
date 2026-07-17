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

func TestBotVerifierHappyPath(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify-bot", http.StatusOK, `{
		"bot_uid": "b-42",
		"bot_name": "helper",
		"role": "assistant",
		"owner_uid": "u-1",
		"owner_name": "Alice",
		"space_id": "s-1"
	}`)
	cfg := testConfig(ms.URL())
	v := NewBotTokenVerifier(cfg)

	p, err := v.Verify(context.Background(), "bf_"+strings.Repeat("a", 32))
	require.NoError(t, err)
	assert.Equal(t, KindBot, p.Kind)
	assert.Equal(t, "b-42", p.UID)
	assert.Equal(t, "helper", p.Name)
	assert.Equal(t, "assistant", p.Role)
	assert.Equal(t, "u-1", p.OwnerUID)
	assert.Equal(t, "Alice", p.OwnerName)
	assert.Equal(t, "s-1", p.SpaceID)
	assert.Equal(t, []string{"b-42"}, p.RelatedUIDs)
	assert.Equal(t, ContextNotRequested, p.Context.Kind)

	reqs := ms.Requests()
	require.Len(t, reqs, 1)
	assert.Empty(t, reqs[0].Query, "bot verifier MUST NOT send include=context")
	assert.Contains(t, string(reqs[0].Body), `"bot_token":"bf_`)
}

func TestBotVerifierEmptySpaceIDRejected(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify-bot", http.StatusOK, `{"bot_uid":"b-1","space_id":""}`)
	cfg := testConfig(ms.URL())
	v := NewBotTokenVerifier(cfg)

	_, err := v.Verify(context.Background(), "bf_"+strings.Repeat("a", 32))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredential)
}

func TestBotVerifierEmptyBotUIDRejected(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify-bot", http.StatusOK, `{"bot_uid":"","space_id":"s-1"}`)
	cfg := testConfig(ms.URL())
	v := NewBotTokenVerifier(cfg)

	_, err := v.Verify(context.Background(), "bf_"+strings.Repeat("a", 32))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredential)
}

func TestBotVerifier401(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify-bot", http.StatusUnauthorized, `{"error":"bad"}`)
	cfg := testConfig(ms.URL())
	v := NewBotTokenVerifier(cfg)

	_, err := v.Verify(context.Background(), "bf_"+strings.Repeat("a", 32))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredential)
}

func TestBotVerifier403(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify-bot", http.StatusForbidden, `{"error":"disabled"}`)
	cfg := testConfig(ms.URL())
	v := NewBotTokenVerifier(cfg)

	_, err := v.Verify(context.Background(), "bf_"+strings.Repeat("a", 32))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrDisabled)
}

func TestBotVerifierAppPrefixShortCircuit(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	cfg := testConfig(ms.URL())
	v := NewBotTokenVerifier(cfg)

	_, err := v.Verify(context.Background(), "app_"+strings.Repeat("a", 32))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredential)
	assert.Empty(t, ms.Requests(), "app_ prefix MUST short-circuit without touching the network")
}

func TestBotVerifierEmptyCredentialShortCircuit(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	cfg := testConfig(ms.URL())
	v := NewBotTokenVerifier(cfg)

	_, err := v.Verify(context.Background(), "")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredential)
	assert.Empty(t, ms.Requests())
}

func TestBotVerifierCachePositive(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify-bot", http.StatusOK,
		`{"bot_uid":"b-1","space_id":"s-1"}`)
	cfg := testConfig(ms.URL())
	v := NewBotTokenVerifier(cfg)

	tok := "bf_" + strings.Repeat("a", 32)
	first, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)
	second, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)

	assert.NotSame(t, first, second, "Verify must return a defensive clone per call")
	assert.Equal(t, first, second, "clones must be value-equal")
	assert.Len(t, ms.Requests(), 1)
}

func TestBotVerifierCacheKeyPrefix(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify-bot", http.StatusOK,
		`{"bot_uid":"b-1","space_id":"s-1"}`)
	cfg := testConfig(ms.URL())
	v := NewBotTokenVerifier(cfg)

	tok := "bf_" + strings.Repeat("a", 32)
	_, err := v.Verify(context.Background(), tok)
	require.NoError(t, err)

	// Positive key must exist under b: prefix.
	posKey := "b:" + HashCacheKey(tok)
	val, ok := cfg.Cache.Get(context.Background(), posKey)
	require.True(t, ok)
	require.NotNil(t, val)

	// Session/apikey prefixes must NOT have this key.
	_, ok = cfg.Cache.Get(context.Background(), "s:"+HashCacheKey(tok))
	assert.False(t, ok)
}

func TestBotVerifierNetworkFailure(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	url := ms.URL()
	ms.Close()
	cfg := testConfig(url)
	v := NewBotTokenVerifier(cfg)

	_, err := v.Verify(context.Background(), "bf_"+strings.Repeat("a", 32))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInfraFailure)
}

func TestBotVerifierDecodeError(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify-bot", http.StatusOK, `not json`)
	cfg := testConfig(ms.URL())
	v := NewBotTokenVerifier(cfg)

	_, err := v.Verify(context.Background(), "bf_"+strings.Repeat("a", 32))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInfraFailure)
}

func TestBotVerifierKind(t *testing.T) {
	v := NewBotTokenVerifier(&Config{BaseURL: "http://example.com"})
	assert.Equal(t, KindBot, v.Kind())
}
