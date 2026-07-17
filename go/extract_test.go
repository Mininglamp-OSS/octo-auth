package octoauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newReqWithHeaders(t *testing.T, headers map[string]string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestExtractCredentialTable(t *testing.T) {
	sessionTok := "9c2f7a4e0b1e4b3a83c1a5d8e6f0a1b2"
	apiKeyTok := "uk_" + strings.Repeat("k", 32)
	botTok := "bf_" + strings.Repeat("b", 32)
	appTok := "app_" + strings.Repeat("a", 32)

	tests := []struct {
		name     string
		headers  map[string]string
		wantKind PrincipalKind
		wantRaw  string
		wantErr  bool
	}{
		{
			name:    "no_headers",
			headers: map[string]string{},
			wantErr: true,
		},
		{
			name:     "bearer_session",
			headers:  map[string]string{"Authorization": "Bearer " + sessionTok},
			wantKind: KindSession,
			wantRaw:  sessionTok,
		},
		{
			name:     "bearer_lowercase_scheme",
			headers:  map[string]string{"Authorization": "bearer " + sessionTok},
			wantKind: KindSession,
			wantRaw:  sessionTok,
		},
		{
			name:     "bearer_mixedcase_scheme",
			headers:  map[string]string{"Authorization": "BeArEr " + sessionTok},
			wantKind: KindSession,
			wantRaw:  sessionTok,
		},
		{
			name:     "bearer_api_key",
			headers:  map[string]string{"Authorization": "Bearer " + apiKeyTok},
			wantKind: KindAPIKey,
			wantRaw:  apiKeyTok,
		},
		{
			name:     "bearer_bot",
			headers:  map[string]string{"Authorization": "Bearer " + botTok},
			wantKind: KindBot,
			wantRaw:  botTok,
		},
		{
			name:     "app_reserved_forwarded_to_bot_kind",
			headers:  map[string]string{"Authorization": "Bearer " + appTok},
			wantKind: KindBot,
			wantRaw:  appTok,
		},
		{
			name:     "token_header_only",
			headers:  map[string]string{"token": sessionTok},
			wantKind: KindSession,
			wantRaw:  sessionTok,
		},
		{
			name:     "token_header_apikey",
			headers:  map[string]string{"token": apiKeyTok},
			wantKind: KindAPIKey,
			wantRaw:  apiKeyTok,
		},
		{
			name: "authorization_priority_over_token_header",
			headers: map[string]string{
				"Authorization": "Bearer " + apiKeyTok,
				"token":         sessionTok,
			},
			wantKind: KindAPIKey,
			wantRaw:  apiKeyTok,
		},
		{
			name: "authorization_non_bearer_falls_back_to_token_header",
			headers: map[string]string{
				"Authorization": "Basic dXNlcjpwYXNz",
				"token":         sessionTok,
			},
			wantKind: KindSession,
			wantRaw:  sessionTok,
		},
		{
			name:    "apikey_too_short_rejected",
			headers: map[string]string{"token": "uk_short"},
			wantErr: true,
		},
		{
			name:    "authorization_bearer_empty_token",
			headers: map[string]string{"Authorization": "Bearer "},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := newReqWithHeaders(t, tc.headers)
			cred, err := ExtractCredential(r)
			if tc.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, ErrInvalidCredential)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantKind, cred.Kind)
			assert.Equal(t, tc.wantRaw, cred.Raw)
		})
	}
}

func TestExtractCredentialNilRequest(t *testing.T) {
	_, err := ExtractCredential(nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredential)
}

func TestValidateAPIKey(t *testing.T) {
	valid := "uk_" + strings.Repeat("k", 32)
	assert.NoError(t, ValidateAPIKey(valid))

	assert.Error(t, ValidateAPIKey("uk_short"))
	assert.Error(t, ValidateAPIKey("bf_"+strings.Repeat("b", 32)))
	assert.Error(t, ValidateAPIKey(""))
}

func TestValidateBotToken(t *testing.T) {
	assert.NoError(t, ValidateBotToken("bf_"+strings.Repeat("b", 32)))
	assert.NoError(t, ValidateBotToken("app_"+strings.Repeat("a", 32)))

	assert.Error(t, ValidateBotToken("bf_"))
	assert.Error(t, ValidateBotToken("uk_"+strings.Repeat("k", 32)))
	assert.Error(t, ValidateBotToken("plain"))
}

func TestStripBearer(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Bearer abc", "abc"},
		{"bearer abc", "abc"},
		{"BEARER   abc  ", "abc"},
		{"Bearer\tabc", "abc"},
		{"Basic abc", ""},
		{"Bearerabc", ""}, // no separating whitespace
		{"", ""},
		{"Bearer", ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, stripBearer(c.in), c.in)
	}
}

func TestExtractCredentialPrefixConstantsMatchDoc(t *testing.T) {
	// Sanity: constants match the strings referenced in design doc §3 / §7.
	assert.Equal(t, "uk_", PrefixUK)
	assert.Equal(t, "bf_", PrefixBF)
	assert.Equal(t, "app_", PrefixApp)
	assert.Equal(t, 35, MinAPIKeyLength)
}
