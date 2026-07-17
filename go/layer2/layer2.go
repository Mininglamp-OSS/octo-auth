// Package layer2 issues and verifies short-lived JWT tokens used by
// hocuspocus-style long-lived connections (see design doc §10).
//
// The typical flow is: a service already authenticated by octo-server
// issues a layer-2 token good for a few minutes; the target service
// verifies the token locally on every message without another round-trip
// to octo-server. Callers still enforce the permission_epoch check
// themselves so revocations propagate within the token's remaining TTL.
//
// v1 supports HS256 only. EdDSA support is a documented v1.1 gap.
package layer2

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// DefaultTTL is the fallback TTL used when [IssueOptions.TTL] is zero. Five
// minutes matches docs-backend's COLLAB_TOKEN_TTL_SECONDS default.
const DefaultTTL = 5 * time.Minute

// MinHS256KeySize is the minimum acceptable HS256 secret length in bytes.
// golang-jwt technically accepts any []byte but shorter secrets defeat the
// whole point of HMAC — 32 bytes gives 256-bit security.
const MinHS256KeySize = 32

// Supported signature algorithms.
const (
	AlgHS256 = "HS256"
	// AlgEdDSA is accepted as a valid string but returns
	// [ErrUnsupportedAlgorithm] at Issue / Verify time — v1 is HS256-only.
	AlgEdDSA = "EdDSA"
)

// Sentinel errors returned by [IssueShortLivedToken] and
// [VerifyShortLivedToken]. Callers can use [errors.Is] for structured
// handling.
var (
	ErrUnsupportedAlgorithm = errors.New("layer2: unsupported signature algorithm (v1 supports HS256 only)")
	ErrMissingUID           = errors.New("layer2: claims missing required uid")
	ErrMissingSigKey        = errors.New("layer2: SigKey is required")
	ErrTokenExpired         = errors.New("layer2: token expired")
	ErrTokenInvalid         = errors.New("layer2: token invalid")
	ErrKeyTooShort          = fmt.Errorf("layer2: HS256 secret must be at least %d bytes", MinHS256KeySize)
)

// ShortLivedClaims is the full payload placed into a layer-2 JWT. All five
// fields are round-tripped by [IssueShortLivedToken] / [VerifyShortLivedToken].
//
// ExpiresAt is derived from IssueOptions.TTL at issue time; callers do not
// need to populate it. It IS populated on the struct returned by Verify
// so callers can render it back to the client if needed.
type ShortLivedClaims struct {
	UID             string
	DocumentName    string
	Role            string
	PermissionEpoch int64
	ExpiresAt       time.Time
}

// IssueOptions configures a call to [IssueShortLivedToken].
type IssueOptions struct {
	Claims ShortLivedClaims
	TTL    time.Duration // default DefaultTTL when zero
	SigKey []byte
	SigAlg string
}

// VerifyOptions configures a call to [VerifyShortLivedToken].
type VerifyOptions struct {
	SigKey []byte
	SigAlg string
}

// IssueShortLivedToken signs a JWT containing opts.Claims and returns the
// compact serialization. The exp claim is set to now + opts.TTL.
//
// Errors:
//   - [ErrMissingUID] when Claims.UID is empty
//   - [ErrMissingSigKey] when SigKey is nil / empty
//   - [ErrKeyTooShort] when HS256 SigKey is under MinHS256KeySize
//   - [ErrUnsupportedAlgorithm] when SigAlg is EdDSA (v1 gap) or unknown
func IssueShortLivedToken(opts IssueOptions) (string, error) {
	if opts.Claims.UID == "" {
		return "", ErrMissingUID
	}
	if len(opts.SigKey) == 0 {
		return "", ErrMissingSigKey
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	expiresAt := time.Now().Add(ttl)

	switch opts.SigAlg {
	case AlgHS256:
		if len(opts.SigKey) < MinHS256KeySize {
			return "", ErrKeyTooShort
		}
	case AlgEdDSA:
		return "", ErrUnsupportedAlgorithm
	default:
		return "", fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, opts.SigAlg)
	}

	claims := jwt.MapClaims{
		"uid":              opts.Claims.UID,
		"document_name":    opts.Claims.DocumentName,
		"role":             opts.Claims.Role,
		"permission_epoch": opts.Claims.PermissionEpoch,
		"exp":              expiresAt.Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(opts.SigKey)
	if err != nil {
		return "", fmt.Errorf("layer2: sign: %w", err)
	}
	return signed, nil
}

// VerifyShortLivedToken parses tokenStr, verifies the signature and
// expiration, and returns the reconstituted claims.
//
// Errors:
//   - [ErrMissingSigKey] when SigKey is nil / empty
//   - [ErrUnsupportedAlgorithm] when SigAlg is EdDSA or unknown
//   - [ErrTokenExpired] when the exp claim is in the past
//   - [ErrTokenInvalid] for signature-mismatch, tampered payload,
//     malformed token, missing required claims (currently just uid),
//     or any other JWT-parse failure. The underlying jwt error is wrapped
//     via [errors.Unwrap] for debugging.
func VerifyShortLivedToken(tokenStr string, opts VerifyOptions) (*ShortLivedClaims, error) {
	if len(opts.SigKey) == 0 {
		return nil, ErrMissingSigKey
	}
	switch opts.SigAlg {
	case AlgHS256:
		// OK
	case AlgEdDSA:
		return nil, ErrUnsupportedAlgorithm
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, opts.SigAlg)
	}

	parsed, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		// Reject "alg: none" and any non-HMAC signing method the token
		// might advertise — an attacker-controlled header can otherwise
		// swap the algorithm.
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return opts.SigKey, nil
	}, jwt.WithValidMethods([]string{AlgHS256}))
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("%w: %w", ErrTokenInvalid, err)
	}
	if parsed == nil || !parsed.Valid {
		return nil, ErrTokenInvalid
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrTokenInvalid
	}

	out, err := shortLivedClaimsFromMap(claims)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// shortLivedClaimsFromMap reconstructs a ShortLivedClaims from the parsed
// jwt.MapClaims. Missing uid is treated as invalid; missing optional fields
// fall through to their zero values.
func shortLivedClaimsFromMap(m jwt.MapClaims) (*ShortLivedClaims, error) {
	uid, _ := m["uid"].(string)
	if uid == "" {
		return nil, fmt.Errorf("%w: missing uid", ErrTokenInvalid)
	}
	out := &ShortLivedClaims{
		UID:          uid,
		DocumentName: stringClaim(m, "document_name"),
		Role:         stringClaim(m, "role"),
	}
	// permission_epoch: JSON numbers round-trip as float64 through
	// encoding/json — convert back to int64 without losing precision for
	// realistic epoch counters.
	if v, ok := m["permission_epoch"]; ok {
		switch n := v.(type) {
		case float64:
			out.PermissionEpoch = int64(n)
		case int64:
			out.PermissionEpoch = n
		case int:
			out.PermissionEpoch = int64(n)
		}
	}
	if exp, ok := m["exp"]; ok {
		switch n := exp.(type) {
		case float64:
			out.ExpiresAt = time.Unix(int64(n), 0).UTC()
		case int64:
			out.ExpiresAt = time.Unix(n, 0).UTC()
		}
	}
	return out, nil
}

func stringClaim(m jwt.MapClaims, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
