package nethttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	octoauth "github.com/Mininglamp-OSS/octo-auth/go"
	"github.com/stretchr/testify/require"
)

type fakeBotResolver struct {
	called bool
	input  octoauth.ResolveRequest
}

func (f *fakeBotResolver) Resolve(_ context.Context, _ string, req octoauth.ResolveRequest) (*octoauth.ResolvedPrincipal, error) {
	f.called = true
	f.input = req
	if req.SpaceID == "" {
		return nil, &octoauth.Error{Kind: octoauth.ErrKindInvalidRequest, Message: "space_id is required"}
	}
	return &octoauth.ResolvedPrincipal{
		Mode:    req.Mode,
		Actor:   octoauth.ResolvedIdentity{UID: "bot-1", Kind: "BOT", SpaceID: req.SpaceID},
		Subject: octoauth.ResolvedIdentity{UID: "owner-1", Kind: "HUMAN", SpaceID: req.SpaceID},
	}, nil
}

func TestWrapBotResolveBindsActionToRoute(t *testing.T) {
	resolver := &fakeBotResolver{}
	var got *octoauth.ResolvedPrincipal
	handler := WrapBotResolve(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = BotResolvedPrincipal(r.Context())
		w.WriteHeader(http.StatusNoContent)
	}), BotResolveOptions{Resolver: resolver, Mode: octoauth.ModeOBO, Action: "project.read"})
	req := httptest.NewRequest(http.MethodGet, "/projects?space_id=S&obo=true&action=admin.write", nil)
	req.Header.Set("Authorization", "Bearer bf_secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusNoContent, w.Code)
	require.True(t, resolver.called)
	require.Equal(t, "project.read", resolver.input.Action)
	require.Equal(t, "S", resolver.input.SpaceID)
	require.Equal(t, "owner-1", got.Subject.UID)
}

func TestWrapBotResolveMissingMarkerDoesNotFallBack(t *testing.T) {
	resolver := &fakeBotResolver{}
	handler := WrapBotResolve(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("business handler must not run")
	}), BotResolveOptions{Resolver: resolver, Mode: octoauth.ModeOBO, Action: "project.read"})
	req := httptest.NewRequest(http.MethodGet, "/projects?space_id=S", nil)
	req.Header.Set("Authorization", "Bearer bf_secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.False(t, resolver.called)
}

func TestWrapBotResolveRejectsAmbiguousCallerInput(t *testing.T) {
	tests := []struct {
		name   string
		mode   octoauth.BotResolveMode
		action string
		url    string
		called bool
	}{
		{name: "empty marker on AS_BOT", mode: octoauth.ModeAsBot, url: "/projects?space_id=S&obo=", called: false},
		{name: "duplicate OBO marker", mode: octoauth.ModeOBO, action: "project.read", url: "/projects?space_id=S&obo=true&obo=true", called: false},
		{name: "caller-selected subject", mode: octoauth.ModeOBO, action: "project.read", url: "/projects?space_id=S&obo=true&human_uid=H", called: false},
		{name: "duplicate Space", mode: octoauth.ModeOBO, action: "project.read", url: "/projects?space_id=S1&space_id=S2&obo=true", called: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver := &fakeBotResolver{}
			handler := WrapBotResolve(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("business handler must not run")
			}), BotResolveOptions{Resolver: resolver, Mode: tt.mode, Action: tt.action})
			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			req.Header.Set("Authorization", "Bearer bf_secret")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, req)
			require.Equal(t, http.StatusBadRequest, w.Code)
			require.Equal(t, tt.called, resolver.called)
		})
	}
}
