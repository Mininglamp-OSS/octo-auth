// Package enrich centralizes the X-Space-Id enrichment logic used by every
// middleware factory (gin / echo / net-http / wkhttp). It is an internal
// package so it never becomes part of the SDK's public API.
package enrich

import (
	octoauth "github.com/Mininglamp-OSS/octo-auth/go"
)

// HeaderReader is a framework-agnostic single-header accessor. Gin's
// c.GetHeader, echo's c.Request().Header.Get, and http.Header.Get all fit
// this shape.
type HeaderReader func(name string) string

// SpaceFromHeader applies the X-Space-Id enrichment rules defined in the
// design doc §8.1 (and matching fleet's §12b implementation).
//
// The rules, in order:
//  1. If p is nil, or header is empty, or the caller-supplied header value
//     is empty, do nothing.
//  2. Only session-realm principals are enriched — bot and api-key realms
//     already carry a server-authoritative SpaceID.
//  3. Based on Principal.Context.Kind:
//     - ContextIncluded (v2 server): the sid MUST be in Context.Spaces or
//     the request is rejected with ErrForbidden (fail-closed).
//     - ContextNotIncluded / ContextUnknownServer: fail-closed — the SDK
//     refuses to bind an unverified client-supplied space id. This matches
//     the wire contract (contract/auth-v1.yaml §fail-closed rules) and
//     prevents cross-space authorization bypass on the default path where
//     a v3 server omits context_included via omitempty.
//     - ContextNotRequested: no-op (defensive; should never hit here).
//
// The mutation on p is direct — callers should Clone() before invoking this
// helper if p may be shared (e.g. cached).
func SpaceFromHeader(p *octoauth.Principal, header string, read HeaderReader) error {
	if p == nil || header == "" || read == nil {
		return nil
	}
	if p.Kind != octoauth.KindSession {
		return nil
	}
	sid := read(header)
	if sid == "" {
		return nil
	}
	switch p.Context.Kind {
	case octoauth.ContextIncluded:
		if !containsString(p.Context.Spaces, sid) {
			return &octoauth.Error{
				Kind:     octoauth.ErrKindForbidden,
				Message:  "requested space is not in principal's authorized set",
				Verifier: octoauth.KindSession,
			}
		}
		p.SpaceID = sid
	case octoauth.ContextNotIncluded, octoauth.ContextUnknownServer:
		// Fail-closed: the server did not affirmatively confirm the caller's
		// space membership, so trusting the client-supplied header would
		// enable cross-space authorization bypass. Callers that need to
		// operate against pre-v2 servers must resolve space membership
		// out-of-band before dispatching.
		return &octoauth.Error{
			Kind:     octoauth.ErrKindForbidden,
			Message:  "requested space is not in principal's authorized set",
			Verifier: octoauth.KindSession,
		}
	case octoauth.ContextNotRequested:
		// no-op: not enrichable
	}
	return nil
}

// containsString reports whether s is present in slice. A local
// implementation keeps the enrich package free of dependencies.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
