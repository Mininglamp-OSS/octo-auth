package octoauth

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeVerifier is a Verifier stub that records the credential it was asked
// about and returns a Principal whose UID mirrors the credential so tests
// can assert dispatch happened correctly.
type fakeVerifier struct {
	kind     PrincipalKind
	lastCtx  context.Context
	lastCred string
	calls    int
	err      error
	returned *Principal
}

func (f *fakeVerifier) Kind() PrincipalKind { return f.kind }

func (f *fakeVerifier) Verify(ctx context.Context, credential string) (*Principal, error) {
	f.calls++
	f.lastCtx = ctx
	f.lastCred = credential
	if f.err != nil {
		return nil, f.err
	}
	if f.returned != nil {
		return f.returned, nil
	}
	return &Principal{Kind: f.kind, UID: credential}, nil
}

func TestClassifyCredential(t *testing.T) {
	tests := []struct {
		name       string
		credential string
		wantKind   PrincipalKind
		wantErr    bool
	}{
		{name: "empty", credential: "", wantErr: true},
		{name: "session_uuid", credential: "9c2f7a4e0b1e4b3a83c1a5d8e6f0a1b2", wantKind: KindSession},
		{name: "session_arbitrary", credential: "hello-world", wantKind: KindSession},
		{name: "bot_bf_prefix", credential: "bf_" + strings.Repeat("a", 32), wantKind: KindBot},
		{name: "bot_app_reserved", credential: "app_" + strings.Repeat("a", 32), wantKind: KindBot},
		{name: "apikey_valid_len35", credential: "uk_" + strings.Repeat("a", 32), wantKind: KindAPIKey},
		{name: "apikey_too_short", credential: "uk_short", wantErr: true},
		{name: "apikey_boundary_len34", credential: "uk_" + strings.Repeat("a", 31), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := classifyCredential(tc.credential)
			if tc.wantErr {
				require.Error(t, err)
				var authErr *Error
				require.ErrorAs(t, err, &authErr)
				assert.Equal(t, ErrKindInvalidCredential, authErr.Kind)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantKind, got)
		})
	}
}

func TestNewMultiVerifierDispatch(t *testing.T) {
	sess := &fakeVerifier{kind: KindSession}
	bot := &fakeVerifier{kind: KindBot}
	key := &fakeVerifier{kind: KindAPIKey}
	m := NewMultiVerifier(sess, bot, key)

	ctx := context.Background()

	t.Run("session_dispatch", func(t *testing.T) {
		p, err := m.Verify(ctx, "session-token-xyz")
		require.NoError(t, err)
		assert.Equal(t, KindSession, p.Kind)
		assert.Equal(t, "session-token-xyz", sess.lastCred)
		assert.Zero(t, bot.calls)
		assert.Zero(t, key.calls)
	})

	t.Run("bot_dispatch", func(t *testing.T) {
		bot.calls = 0
		_, err := m.Verify(ctx, "bf_"+strings.Repeat("b", 32))
		require.NoError(t, err)
		assert.Equal(t, 1, bot.calls)
	})

	t.Run("app_reserved_forwarded_to_bot", func(t *testing.T) {
		bot.calls = 0
		_, err := m.Verify(ctx, "app_"+strings.Repeat("c", 32))
		require.NoError(t, err)
		assert.Equal(t, 1, bot.calls, "app_ prefix must forward to bot verifier")
	})

	t.Run("apikey_dispatch", func(t *testing.T) {
		key.calls = 0
		_, err := m.Verify(ctx, "uk_"+strings.Repeat("d", 32))
		require.NoError(t, err)
		assert.Equal(t, 1, key.calls)
	})

	t.Run("apikey_too_short_rejected", func(t *testing.T) {
		key.calls = 0
		_, err := m.Verify(ctx, "uk_short")
		require.Error(t, err)
		assert.Zero(t, key.calls)
		assert.True(t, m.(*multiVerifier) != nil)
		assert.ErrorIs(t, err, ErrInvalidCredential)
	})

	t.Run("empty_rejected", func(t *testing.T) {
		_, err := m.Verify(ctx, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidCredential)
	})
}

func TestNewMultiVerifierNilChildIgnored(t *testing.T) {
	sess := &fakeVerifier{kind: KindSession}
	m := NewMultiVerifier(nil, sess, nil)

	_, err := m.Verify(context.Background(), "anything")
	require.NoError(t, err)
	assert.Equal(t, 1, sess.calls)
}

func TestMultiVerifierRegisterReplaces(t *testing.T) {
	first := &fakeVerifier{kind: KindSession}
	m := NewMultiVerifier(first)

	second := &fakeVerifier{kind: KindSession}
	m.Register(second)

	_, err := m.Verify(context.Background(), "session-x")
	require.NoError(t, err)
	assert.Zero(t, first.calls, "first verifier must be replaced")
	assert.Equal(t, 1, second.calls)
}

func TestMultiVerifierMissingChildErrors(t *testing.T) {
	m := NewMultiVerifier() // no children registered
	_, err := m.Verify(context.Background(), "bf_"+strings.Repeat("x", 32))
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredential)
	var authErr *Error
	require.ErrorAs(t, err, &authErr)
	assert.Equal(t, KindBot, authErr.Verifier)
}

func TestMultiVerifierPropagatesChildError(t *testing.T) {
	failing := &fakeVerifier{kind: KindSession, err: &Error{Kind: ErrKindInfraFailure, Message: "boom"}}
	m := NewMultiVerifier(failing)
	_, err := m.Verify(context.Background(), "session-x")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInfraFailure)
}

func TestMultiVerifierKindLabel(t *testing.T) {
	m := NewMultiVerifier()
	assert.Equal(t, PrincipalKind("multi"), m.Kind())
}

func TestPrincipalContextKindZeroIsNotRequested(t *testing.T) {
	var pc PrincipalContext
	assert.Equal(t, ContextNotRequested, pc.Kind)
}
