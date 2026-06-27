package auth

import "testing"

func TestScopeAllows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		scope Scope
		kind  AuthKind
		want  bool
	}{
		{ScopeAny, AuthKindSession, true},
		{ScopeAny, AuthKindBot, true},
		{ScopeAny, AuthKindAPIKey, true},
		{ScopeAny, AuthKindUnknown, false},
		{ScopeWeb, AuthKindSession, true},
		{ScopeWeb, AuthKindBot, false},
		{ScopeWeb, AuthKindAPIKey, false},
		{ScopeBot, AuthKindSession, false},
		{ScopeBot, AuthKindBot, true},
		{ScopeBot, AuthKindAPIKey, false},
		{ScopeDaemon, AuthKindSession, false},
		{ScopeDaemon, AuthKindBot, false},
		{ScopeDaemon, AuthKindAPIKey, true},
	}
	for _, tc := range cases {
		if got := tc.scope.allows(tc.kind); got != tc.want {
			t.Errorf("Scope(%s).allows(%s) = %v, want %v", tc.scope, tc.kind, got, tc.want)
		}
	}
}

func TestKindFromPrefix(t *testing.T) {
	t.Parallel()
	cases := []struct {
		token string
		want  AuthKind
	}{
		{"uk_abc", AuthKindAPIKey},
		{"bf_xyz", AuthKindBot},
		{"app_xyz", AuthKindBot},
		{"plain-user-token", AuthKindSession},
		{"", AuthKindSession}, // legacy: anything without a known prefix is session
	}
	for _, tc := range cases {
		if got := kindFromPrefix(tc.token); got != tc.want {
			t.Errorf("kindFromPrefix(%q) = %v, want %v", tc.token, got, tc.want)
		}
	}
}
