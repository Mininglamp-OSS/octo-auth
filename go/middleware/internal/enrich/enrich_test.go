package enrich

import (
	"errors"
	"testing"

	octoauth "github.com/Mininglamp-OSS/octo-auth/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func staticReader(values map[string]string) HeaderReader {
	return func(name string) string { return values[name] }
}

func TestSpaceFromHeaderNoOpPaths(t *testing.T) {
	read := staticReader(map[string]string{"X-Space-Id": "s-1"})

	// nil principal
	assert.NoError(t, SpaceFromHeader(nil, "X-Space-Id", read))

	// empty header name
	p1 := &octoauth.Principal{Kind: octoauth.KindSession}
	assert.NoError(t, SpaceFromHeader(p1, "", read))
	assert.Empty(t, p1.SpaceID)

	// nil reader
	p2 := &octoauth.Principal{Kind: octoauth.KindSession}
	assert.NoError(t, SpaceFromHeader(p2, "X-Space-Id", nil))
	assert.Empty(t, p2.SpaceID)

	// non-session principal (bot)
	pBot := &octoauth.Principal{Kind: octoauth.KindBot, SpaceID: "s-orig"}
	assert.NoError(t, SpaceFromHeader(pBot, "X-Space-Id", read))
	assert.Equal(t, "s-orig", pBot.SpaceID, "bot SpaceID must be untouched")

	// non-session principal (apikey)
	pKey := &octoauth.Principal{Kind: octoauth.KindAPIKey, SpaceID: "s-orig"}
	assert.NoError(t, SpaceFromHeader(pKey, "X-Space-Id", read))
	assert.Equal(t, "s-orig", pKey.SpaceID)

	// header value empty
	pEmpty := &octoauth.Principal{Kind: octoauth.KindSession}
	assert.NoError(t, SpaceFromHeader(pEmpty, "X-Space-Id", staticReader(nil)))
	assert.Empty(t, pEmpty.SpaceID)
}

func TestSpaceFromHeaderIncludedHardCheckPass(t *testing.T) {
	p := &octoauth.Principal{
		Kind: octoauth.KindSession,
		Context: octoauth.PrincipalContext{
			Kind:   octoauth.ContextIncluded,
			Spaces: []string{"s-a", "s-b"},
		},
	}
	read := staticReader(map[string]string{"X-Space-Id": "s-b"})
	require.NoError(t, SpaceFromHeader(p, "X-Space-Id", read))
	assert.Equal(t, "s-b", p.SpaceID)
}

func TestSpaceFromHeaderIncludedHardCheckReject(t *testing.T) {
	p := &octoauth.Principal{
		Kind: octoauth.KindSession,
		Context: octoauth.PrincipalContext{
			Kind:   octoauth.ContextIncluded,
			Spaces: []string{"s-a", "s-b"},
		},
	}
	read := staticReader(map[string]string{"X-Space-Id": "s-nope"})
	err := SpaceFromHeader(p, "X-Space-Id", read)
	require.Error(t, err)
	assert.True(t, errors.Is(err, octoauth.ErrForbidden))
	assert.Empty(t, p.SpaceID, "SpaceID MUST NOT be set when membership check fails")
}

func TestSpaceFromHeaderNotIncludedPreV2Trust(t *testing.T) {
	p := &octoauth.Principal{
		Kind: octoauth.KindSession,
		Context: octoauth.PrincipalContext{
			Kind: octoauth.ContextNotIncluded,
		},
	}
	read := staticReader(map[string]string{"X-Space-Id": "s-1"})
	require.NoError(t, SpaceFromHeader(p, "X-Space-Id", read))
	assert.Equal(t, "s-1", p.SpaceID)
}

func TestSpaceFromHeaderUnknownServerPreV2Trust(t *testing.T) {
	p := &octoauth.Principal{
		Kind: octoauth.KindSession,
		Context: octoauth.PrincipalContext{
			Kind: octoauth.ContextUnknownServer,
		},
	}
	read := staticReader(map[string]string{"X-Space-Id": "s-1"})
	require.NoError(t, SpaceFromHeader(p, "X-Space-Id", read))
	assert.Equal(t, "s-1", p.SpaceID)
}

func TestSpaceFromHeaderNotRequestedNoOp(t *testing.T) {
	p := &octoauth.Principal{
		Kind: octoauth.KindSession,
		Context: octoauth.PrincipalContext{
			Kind: octoauth.ContextNotRequested,
		},
		SpaceID: "orig",
	}
	read := staticReader(map[string]string{"X-Space-Id": "s-1"})
	require.NoError(t, SpaceFromHeader(p, "X-Space-Id", read))
	assert.Equal(t, "orig", p.SpaceID, "NotRequested must be a no-op even for session realm")
}

func TestContainsString(t *testing.T) {
	assert.True(t, containsString([]string{"a", "b"}, "a"))
	assert.True(t, containsString([]string{"a", "b"}, "b"))
	assert.False(t, containsString([]string{"a", "b"}, "c"))
	assert.False(t, containsString(nil, "a"))
	assert.False(t, containsString([]string{}, "a"))
}
