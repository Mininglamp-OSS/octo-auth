package octoauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrincipalCloneNilSafe(t *testing.T) {
	var p *Principal
	assert.Nil(t, p.Clone())
}

func TestPrincipalCloneShallowFieldsCopied(t *testing.T) {
	orig := &Principal{
		Kind:      KindSession,
		UID:       "u-1",
		Name:      "Alice",
		Role:      "user",
		SpaceID:   "s-1",
		OwnerUID:  "",
		OwnerName: "",
	}
	clone := orig.Clone()
	require.NotNil(t, clone)
	assert.NotSame(t, orig, clone, "Clone must return a fresh *Principal")
	assert.Equal(t, *orig, *clone)

	// Mutation on clone MUST NOT affect orig.
	clone.SpaceID = "s-2"
	clone.Name = "Bob"
	assert.Equal(t, "s-1", orig.SpaceID)
	assert.Equal(t, "Alice", orig.Name)
}

func TestPrincipalCloneSlicesAreIndependent(t *testing.T) {
	orig := &Principal{
		Kind:        KindSession,
		UID:         "u-1",
		RelatedUIDs: []string{"u-1", "b-1"},
	}
	clone := orig.Clone()

	// Append to clone.RelatedUIDs — orig must not see the new entry.
	clone.RelatedUIDs = append(clone.RelatedUIDs, "b-2")
	assert.Equal(t, []string{"u-1", "b-1"}, orig.RelatedUIDs)
	assert.Equal(t, []string{"u-1", "b-1", "b-2"}, clone.RelatedUIDs)

	// Mutate clone.RelatedUIDs[0] in place — orig must see the original value.
	clone.RelatedUIDs[0] = "changed"
	assert.Equal(t, "u-1", orig.RelatedUIDs[0])
}

func TestPrincipalCloneContextSpacesIndependent(t *testing.T) {
	orig := &Principal{
		Kind: KindSession,
		Context: PrincipalContext{
			Kind:   ContextIncluded,
			Spaces: []string{"s-1", "s-2"},
			OwnedBotsBySpace: map[string][]string{
				"s-1": {"b-1"},
				"s-2": {"b-2", "b-3"},
			},
		},
	}
	clone := orig.Clone()

	clone.Context.Spaces[0] = "hacked"
	clone.Context.OwnedBotsBySpace["s-1"][0] = "hacked-bot"
	clone.Context.OwnedBotsBySpace["s-new"] = []string{"b-x"}

	assert.Equal(t, "s-1", orig.Context.Spaces[0])
	assert.Equal(t, "b-1", orig.Context.OwnedBotsBySpace["s-1"][0])
	_, ok := orig.Context.OwnedBotsBySpace["s-new"]
	assert.False(t, ok)
}

func TestPrincipalCloneNilFieldsStayNil(t *testing.T) {
	orig := &Principal{Kind: KindAPIKey, UID: "u-1"}
	clone := orig.Clone()
	assert.Nil(t, clone.RelatedUIDs)
	assert.Nil(t, clone.Context.Spaces)
	assert.Nil(t, clone.Context.OwnedBotsBySpace)
}

func TestPrincipalCloneEmptyMapValues(t *testing.T) {
	orig := &Principal{
		Kind: KindSession,
		Context: PrincipalContext{
			Kind: ContextIncluded,
			OwnedBotsBySpace: map[string][]string{
				"s-empty": nil,
				"s-set":   {"b-1"},
			},
		},
	}
	clone := orig.Clone()
	assert.Nil(t, clone.Context.OwnedBotsBySpace["s-empty"])
	assert.Equal(t, []string{"b-1"}, clone.Context.OwnedBotsBySpace["s-set"])
}
