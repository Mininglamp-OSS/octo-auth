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

func TestFullMultiVerifierEndToEndDispatch(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify", http.StatusOK,
		`{"uid":"u-1","context_included":true}`)
	ms.SetResponse("/v1/auth/verify-bot", http.StatusOK,
		`{"bot_uid":"b-1","space_id":"s-1"}`)
	ms.SetResponse("/v1/auth/verify-api-key", http.StatusOK,
		`{"uid":"u-2","space_id":"s-2","context_included":true}`)
	cfg := testConfig(ms.URL())
	mv := NewFullMultiVerifier(cfg)

	ctx := context.Background()

	sessionP, err := mv.Verify(ctx, "session-token")
	require.NoError(t, err)
	assert.Equal(t, KindSession, sessionP.Kind)
	assert.Equal(t, "u-1", sessionP.UID)

	botP, err := mv.Verify(ctx, "bf_"+strings.Repeat("a", 32))
	require.NoError(t, err)
	assert.Equal(t, KindBot, botP.Kind)
	assert.Equal(t, "b-1", botP.UID)
	assert.Equal(t, "s-1", botP.SpaceID)

	apiP, err := mv.Verify(ctx, "uk_"+strings.Repeat("k", 32))
	require.NoError(t, err)
	assert.Equal(t, KindAPIKey, apiP.Kind)
	assert.Equal(t, "u-2", apiP.UID)
	assert.Equal(t, "s-2", apiP.SpaceID)

	// Each realm hits its dedicated endpoint exactly once.
	reqs := ms.Requests()
	require.Len(t, reqs, 3)
	paths := map[string]int{}
	for _, r := range reqs {
		paths[r.Path]++
	}
	assert.Equal(t, 1, paths["/v1/auth/verify"])
	assert.Equal(t, 1, paths["/v1/auth/verify-bot"])
	assert.Equal(t, 1, paths["/v1/auth/verify-api-key"])
}

func TestFullMultiVerifierSharesCache(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	ms.SetResponse("/v1/auth/verify", http.StatusOK, `{"uid":"u-1"}`)
	cfg := testConfig(ms.URL())
	mv := NewFullMultiVerifier(cfg)

	ctx := context.Background()
	_, err := mv.Verify(ctx, "tok")
	require.NoError(t, err)
	// Second call must be a cache hit — proves the child verifier and any
	// direct call would share cfg.Cache.
	_, err = mv.Verify(ctx, "tok")
	require.NoError(t, err)
	assert.Len(t, ms.Requests(), 1)
}

func TestFullMultiVerifierAppTokenRejectedWithoutHTTP(t *testing.T) {
	ms := testhelpers.NewMockServer(t)
	cfg := testConfig(ms.URL())
	mv := NewFullMultiVerifier(cfg)

	_, err := mv.Verify(context.Background(), "app_"+strings.Repeat("a", 32))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredential)
	assert.Empty(t, ms.Requests(), "app_ MUST short-circuit inside bot verifier")
}
