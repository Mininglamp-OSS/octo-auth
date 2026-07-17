package octoauth

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestErrorKindString(t *testing.T) {
	cases := []struct {
		k    ErrorKind
		want string
	}{
		{ErrKindInvalidCredential, "invalid_credential"},
		{ErrKindDisabled, "disabled"},
		{ErrKindInfraFailure, "infra_failure"},
		{ErrKindPreV2Server, "pre_v2_server"},
		{ErrKindForbidden, "forbidden"},
		{ErrorKind(99), "unknown(99)"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, c.k.String())
	}
}

func TestErrorErrorFormatting(t *testing.T) {
	cause := fmt.Errorf("timeout")
	e := &Error{
		Kind:     ErrKindInfraFailure,
		Message:  "verify call failed",
		Cause:    cause,
		Verifier: KindSession,
	}
	got := e.Error()
	assert.Contains(t, got, "octoauth:")
	assert.Contains(t, got, "infra_failure")
	assert.Contains(t, got, "session")
	assert.Contains(t, got, "verify call failed")
	assert.Contains(t, got, "timeout")
}

func TestErrorErrorFormattingVariants(t *testing.T) {
	msgOnly := &Error{Kind: ErrKindDisabled, Message: "bot disabled"}
	assert.Contains(t, msgOnly.Error(), "bot disabled")

	causeOnly := &Error{Kind: ErrKindInfraFailure, Cause: fmt.Errorf("dial fail")}
	assert.Contains(t, causeOnly.Error(), "dial fail")

	bare := &Error{Kind: ErrKindForbidden}
	assert.Equal(t, "octoauth: forbidden", bare.Error())

	var nilErr *Error
	assert.Equal(t, "<nil octo-auth error>", nilErr.Error())
}

func TestErrorUnwrap(t *testing.T) {
	root := errors.New("root cause")
	e := &Error{Kind: ErrKindInfraFailure, Cause: root}
	assert.Same(t, root, errors.Unwrap(e))

	var nilErr *Error
	assert.Nil(t, nilErr.Unwrap())
}

func TestErrorIsSentinel(t *testing.T) {
	// A freshly constructed Error with the same Kind must satisfy errors.Is.
	freshInvalid := &Error{Kind: ErrKindInvalidCredential, Message: "token expired"}
	require.True(t, errors.Is(freshInvalid, ErrInvalidCredential))
	require.False(t, errors.Is(freshInvalid, ErrDisabled))

	// Sentinel-vs-sentinel compares by Kind.
	assert.True(t, errors.Is(ErrDisabled, ErrDisabled))
	assert.False(t, errors.Is(ErrDisabled, ErrInvalidCredential))

	// Wrapped errors still match via errors.Is via Unwrap chain.
	root := errors.New("net down")
	e := &Error{Kind: ErrKindInfraFailure, Cause: root}
	assert.True(t, errors.Is(e, ErrInfraFailure))
	assert.True(t, errors.Is(e, root))
}

func TestErrorIsRejectsNonError(t *testing.T) {
	e := &Error{Kind: ErrKindInvalidCredential}
	assert.False(t, e.Is(nil))
	assert.False(t, e.Is(errors.New("plain")))
}

func TestErrorAsExtractsPointer(t *testing.T) {
	original := &Error{Kind: ErrKindForbidden, Message: "space mismatch", Verifier: KindSession}
	wrapped := fmt.Errorf("wrap: %w", original)

	var got *Error
	require.True(t, errors.As(wrapped, &got))
	assert.Equal(t, ErrKindForbidden, got.Kind)
	assert.Equal(t, "space mismatch", got.Message)
	assert.Equal(t, KindSession, got.Verifier)
}
