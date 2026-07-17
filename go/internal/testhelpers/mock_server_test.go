package testhelpers

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMockServerRoundTrip(t *testing.T) {
	m := NewMockServer(t)
	m.SetResponse("/v1/auth/verify", http.StatusOK, `{"ok":true}`)

	resp, err := http.Post(m.URL()+"/v1/auth/verify?include=context", "application/json", strings.NewReader(`{"token":"x"}`))
	require.NoError(t, err)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, `{"ok":true}`, string(body))

	reqs := m.Requests()
	require.Len(t, reqs, 1)
	assert.Equal(t, http.MethodPost, reqs[0].Method)
	assert.Equal(t, "/v1/auth/verify", reqs[0].Path)
	assert.Equal(t, "include=context", reqs[0].Query)
	assert.Equal(t, `{"token":"x"}`, string(reqs[0].Body))
}

func TestMockServerUnregisteredPath404(t *testing.T) {
	m := NewMockServer(t)
	resp, err := http.Get(m.URL() + "/nope")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func TestMockServerCustomHeaders(t *testing.T) {
	m := NewMockServer(t)
	m.SetResponseFull("/x", StubResponse{
		Status:  http.StatusTeapot,
		Body:    "brewing",
		Headers: http.Header{"X-Custom": []string{"y"}},
	})

	resp, err := http.Get(m.URL() + "/x")
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusTeapot, resp.StatusCode)
	assert.Equal(t, "y", resp.Header.Get("X-Custom"))
}
