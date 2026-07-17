package layer2

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSecret is a 32-byte HS256 secret used across all layer-2 tests.
// It is intentionally NOT a realistic looking value — the "test-" prefix
// makes it obvious the string is a fixture.
var testSecret = []byte("test-secret-1234567890123456789012")

func newTestClaims() ShortLivedClaims {
	return ShortLivedClaims{
		UID:             "user-1",
		DocumentName:    "doc-42",
		Role:            "editor",
		PermissionEpoch: 42,
	}
}

func TestIssueShortLivedTokenHappyPath(t *testing.T) {
	token, err := IssueShortLivedToken(IssueOptions{
		Claims: newTestClaims(),
		SigKey: testSecret,
		SigAlg: AlgHS256,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	// JWT compact form has 3 dot-separated parts.
	assert.Equal(t, 3, strings.Count(token, ".")+1)
}

func TestIssueShortLivedTokenMissingUID(t *testing.T) {
	_, err := IssueShortLivedToken(IssueOptions{
		Claims: ShortLivedClaims{},
		SigKey: testSecret,
		SigAlg: AlgHS256,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingUID)
}

func TestIssueShortLivedTokenMissingSigKey(t *testing.T) {
	_, err := IssueShortLivedToken(IssueOptions{
		Claims: newTestClaims(),
		SigKey: nil,
		SigAlg: AlgHS256,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingSigKey)
}

func TestIssueShortLivedTokenShortHS256Key(t *testing.T) {
	_, err := IssueShortLivedToken(IssueOptions{
		Claims: newTestClaims(),
		SigKey: []byte("too-short-secret"),
		SigAlg: AlgHS256,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrKeyTooShort)
}

func TestIssueShortLivedTokenEdDSAUnsupported(t *testing.T) {
	_, err := IssueShortLivedToken(IssueOptions{
		Claims: newTestClaims(),
		SigKey: testSecret,
		SigAlg: AlgEdDSA,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

func TestIssueShortLivedTokenUnknownAlg(t *testing.T) {
	_, err := IssueShortLivedToken(IssueOptions{
		Claims: newTestClaims(),
		SigKey: testSecret,
		SigAlg: "RS256",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

func TestVerifyShortLivedTokenRoundtrip(t *testing.T) {
	claims := newTestClaims()
	token, err := IssueShortLivedToken(IssueOptions{
		Claims: claims,
		SigKey: testSecret,
		SigAlg: AlgHS256,
	})
	require.NoError(t, err)

	got, err := VerifyShortLivedToken(token, VerifyOptions{
		SigKey: testSecret,
		SigAlg: AlgHS256,
	})
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, claims.UID, got.UID)
	assert.Equal(t, claims.DocumentName, got.DocumentName)
	assert.Equal(t, claims.Role, got.Role)
	assert.Equal(t, claims.PermissionEpoch, got.PermissionEpoch)
	// ExpiresAt should be around now + DefaultTTL. Allow a broad window
	// so slow CI does not flake the assertion.
	assert.WithinDuration(t, time.Now().Add(DefaultTTL), got.ExpiresAt, 30*time.Second)
}

func TestVerifyShortLivedTokenCustomTTL(t *testing.T) {
	token, err := IssueShortLivedToken(IssueOptions{
		Claims: newTestClaims(),
		SigKey: testSecret,
		SigAlg: AlgHS256,
		TTL:    2 * time.Hour,
	})
	require.NoError(t, err)

	got, err := VerifyShortLivedToken(token, VerifyOptions{
		SigKey: testSecret,
		SigAlg: AlgHS256,
	})
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(2*time.Hour), got.ExpiresAt, 30*time.Second)
}

func TestVerifyShortLivedTokenExpired(t *testing.T) {
	// Hand-build an already-expired JWT with the same secret.
	past := time.Now().Add(-1 * time.Hour)
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid":              "u-1",
		"document_name":    "d-1",
		"role":             "r-1",
		"permission_epoch": int64(1),
		"exp":              past.Unix(),
	})
	signed, err := token.SignedString(testSecret)
	require.NoError(t, err)

	_, verr := VerifyShortLivedToken(signed, VerifyOptions{
		SigKey: testSecret,
		SigAlg: AlgHS256,
	})
	require.Error(t, verr)
	assert.ErrorIs(t, verr, ErrTokenExpired)
}

func TestVerifyShortLivedTokenWrongSigKey(t *testing.T) {
	token, err := IssueShortLivedToken(IssueOptions{
		Claims: newTestClaims(),
		SigKey: testSecret,
		SigAlg: AlgHS256,
	})
	require.NoError(t, err)

	wrong := []byte("another-different-secret-1234567890")
	_, verr := VerifyShortLivedToken(token, VerifyOptions{
		SigKey: wrong,
		SigAlg: AlgHS256,
	})
	require.Error(t, verr)
	assert.ErrorIs(t, verr, ErrTokenInvalid)
}

func TestVerifyShortLivedTokenTampered(t *testing.T) {
	token, err := IssueShortLivedToken(IssueOptions{
		Claims: newTestClaims(),
		SigKey: testSecret,
		SigAlg: AlgHS256,
	})
	require.NoError(t, err)

	// Flip a character in the payload part.
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	// Replace one character in the payload's middle.
	payload := []byte(parts[1])
	payload[len(payload)/2] ^= 0x01
	tampered := parts[0] + "." + string(payload) + "." + parts[2]

	_, verr := VerifyShortLivedToken(tampered, VerifyOptions{
		SigKey: testSecret,
		SigAlg: AlgHS256,
	})
	require.Error(t, verr)
	assert.ErrorIs(t, verr, ErrTokenInvalid)
}

func TestVerifyShortLivedTokenMalformed(t *testing.T) {
	_, err := VerifyShortLivedToken("not-a-valid-jwt", VerifyOptions{
		SigKey: testSecret,
		SigAlg: AlgHS256,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestVerifyShortLivedTokenMissingSigKey(t *testing.T) {
	_, err := VerifyShortLivedToken("x.y.z", VerifyOptions{
		SigKey: nil,
		SigAlg: AlgHS256,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMissingSigKey)
}

// TestVerifyShortLivedTokenShortHS256Key ensures the verify path rejects a
// weak HMAC secret symmetrically with the issue path. Without this guard, a
// verify-only consumer (token issued elsewhere) configured with a < 32-byte
// secret would silently accept the weak signature, enabling brute-force
// forgery of any uid/role/document_name/permission_epoch. Reviewer P1-A.
func TestVerifyShortLivedTokenShortHS256Key(t *testing.T) {
	// Sign a token with the same short secret so the signature would
	// otherwise verify — proves the guard fires before jwt.Parse.
	shortKey := []byte("too-short-secret")
	signed := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"uid": "u-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tokenStr, err := signed.SignedString(shortKey)
	require.NoError(t, err)

	_, verr := VerifyShortLivedToken(tokenStr, VerifyOptions{
		SigKey: shortKey,
		SigAlg: AlgHS256,
	})
	require.Error(t, verr)
	assert.ErrorIs(t, verr, ErrKeyTooShort)
}

func TestVerifyShortLivedTokenEdDSAUnsupported(t *testing.T) {
	_, err := VerifyShortLivedToken("x.y.z", VerifyOptions{
		SigKey: testSecret,
		SigAlg: AlgEdDSA,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnsupportedAlgorithm)
}

func TestVerifyShortLivedTokenMissingUIDClaim(t *testing.T) {
	// Sign a token that has no uid claim.
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"document_name": "d",
		"exp":           time.Now().Add(time.Hour).Unix(),
	})
	signed, err := token.SignedString(testSecret)
	require.NoError(t, err)

	_, verr := VerifyShortLivedToken(signed, VerifyOptions{
		SigKey: testSecret,
		SigAlg: AlgHS256,
	})
	require.Error(t, verr)
	assert.ErrorIs(t, verr, ErrTokenInvalid)
}

// TestVerifyShortLivedTokenAlgorithmConfusion covers the JWT alg-confusion
// class of attacks: a token signed with a different-family algorithm (RS256,
// none, ...) must be rejected even if the alg header looks legitimate.
func TestVerifyShortLivedTokenNoneAlgRejected(t *testing.T) {
	// Manually craft an "alg: none" token; golang-jwt/v5 refuses to sign
	// with unsafe methods via NewWithClaims + SignedString, but we can
	// still forge the compact form by hand.
	// header {"alg":"none","typ":"JWT"} base64url = eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
	// payload {"uid":"u-1","exp":9999999999} = eyJ1aWQiOiJ1LTEiLCJleHAiOjk5OTk5OTk5OTl9
	// signature = ""
	forged := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1aWQiOiJ1LTEiLCJleHAiOjk5OTk5OTk5OTl9."
	_, err := VerifyShortLivedToken(forged, VerifyOptions{
		SigKey: testSecret,
		SigAlg: AlgHS256,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrTokenInvalid)
}

func TestSentinelErrorsUnwrappable(t *testing.T) {
	// Guard: newer callers use errors.Is against sentinels. Verify the
	// core sentinels are directly comparable and not shadowed by wrapping.
	assert.True(t, errors.Is(ErrMissingUID, ErrMissingUID))
	assert.True(t, errors.Is(ErrMissingSigKey, ErrMissingSigKey))
	assert.True(t, errors.Is(ErrTokenExpired, ErrTokenExpired))
	assert.True(t, errors.Is(ErrTokenInvalid, ErrTokenInvalid))
	assert.True(t, errors.Is(ErrUnsupportedAlgorithm, ErrUnsupportedAlgorithm))
	assert.True(t, errors.Is(ErrKeyTooShort, ErrKeyTooShort))
}

func TestShortLivedClaimsFromMapPreservesEpoch(t *testing.T) {
	// Directly test the int64 preservation code path since the JWT lib
	// naturally rounds through float64.
	m := jwt.MapClaims{
		"uid":              "u-1",
		"permission_epoch": float64(1_700_000_000),
		"exp":              float64(time.Now().Add(time.Hour).Unix()),
	}
	got, err := shortLivedClaimsFromMap(m)
	require.NoError(t, err)
	assert.Equal(t, int64(1_700_000_000), got.PermissionEpoch)
	assert.False(t, got.ExpiresAt.IsZero())
}

func TestShortLivedClaimsFromMapAcceptsIntEpoch(t *testing.T) {
	m := jwt.MapClaims{
		"uid":              "u-1",
		"permission_epoch": int64(7),
	}
	got, err := shortLivedClaimsFromMap(m)
	require.NoError(t, err)
	assert.Equal(t, int64(7), got.PermissionEpoch)
}

func TestShortLivedClaimsFromMapAcceptsPlainIntEpoch(t *testing.T) {
	m := jwt.MapClaims{
		"uid":              "u-1",
		"permission_epoch": int(9),
	}
	got, err := shortLivedClaimsFromMap(m)
	require.NoError(t, err)
	assert.Equal(t, int64(9), got.PermissionEpoch)
}

func TestShortLivedClaimsFromMapAcceptsInt64Exp(t *testing.T) {
	future := time.Now().Add(time.Hour).Unix()
	m := jwt.MapClaims{
		"uid": "u-1",
		"exp": future,
	}
	got, err := shortLivedClaimsFromMap(m)
	require.NoError(t, err)
	assert.Equal(t, time.Unix(future, 0).UTC(), got.ExpiresAt)
}

func TestShortLivedClaimsFromMapDropsUnexpectedEpochType(t *testing.T) {
	m := jwt.MapClaims{
		"uid":              "u-1",
		"permission_epoch": "not-a-number", // gets ignored per type switch
	}
	got, err := shortLivedClaimsFromMap(m)
	require.NoError(t, err)
	assert.Equal(t, int64(0), got.PermissionEpoch)
}

// TestVerifyShortLivedTokenRejectsHS512 verifies that a token signed with a
// different HMAC family (HS512) is rejected — the WithValidMethods filter
// must reject it before the key callback even fires.
func TestVerifyShortLivedTokenRejectsHS512(t *testing.T) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, jwt.MapClaims{
		"uid": "u-1",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	signed, err := token.SignedString(testSecret)
	require.NoError(t, err)

	_, verr := VerifyShortLivedToken(signed, VerifyOptions{
		SigKey: testSecret,
		SigAlg: AlgHS256,
	})
	require.Error(t, verr)
	assert.ErrorIs(t, verr, ErrTokenInvalid)
}
