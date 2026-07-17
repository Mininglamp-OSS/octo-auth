// Package testhelpers provides shared test doubles used by SDK verifier
// implementations and integration tests. It is under internal/ so external
// users of the SDK do not depend on it.
package testhelpers

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// StubResponse is the canned response for a given path.
type StubResponse struct {
	Status int
	Body   string
	// Headers overrides the default Content-Type: application/json header
	// when non-nil.
	Headers http.Header
}

// MockServer wraps an httptest.Server with a path-keyed response registry.
// It is intended for verifier unit tests: register the response you want for
// a given endpoint, then point Config.BaseURL at MockServer.URL().
//
// A single MockServer records every request received via Requests() for
// after-the-fact assertions on method / path / headers.
type MockServer struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	responses map[string]StubResponse
	requests  []RecordedRequest
}

// RecordedRequest captures the fields tests typically want to assert on.
// The full *http.Request is not retained to keep the surface area small
// and avoid accidental reads after Close().
type RecordedRequest struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   []byte
}

// NewMockServer builds a MockServer bound to an httptest.NewServer. The
// server is automatically closed when the test completes via t.Cleanup.
func NewMockServer(t *testing.T) *MockServer {
	t.Helper()
	m := &MockServer{
		t:         t,
		responses: make(map[string]StubResponse),
	}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.Close)
	return m
}

// SetResponse registers the canned response for path (matched exactly against
// r.URL.Path — query strings are not considered). Overwrites any prior
// registration for the same path.
func (m *MockServer) SetResponse(path string, status int, body string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses[path] = StubResponse{Status: status, Body: body}
}

// SetResponseFull registers a full StubResponse (with custom headers) for
// path. Overwrites any prior registration.
func (m *MockServer) SetResponseFull(path string, resp StubResponse) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.responses[path] = resp
}

// URL returns the base URL of the underlying httptest.Server.
func (m *MockServer) URL() string { return m.srv.URL }

// Close shuts down the underlying server. Idempotent.
func (m *MockServer) Close() {
	if m.srv != nil {
		m.srv.Close()
	}
}

// Requests returns a defensive copy of all requests received so far.
func (m *MockServer) Requests() []RecordedRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]RecordedRequest, len(m.requests))
	copy(out, m.requests)
	return out
}

func (m *MockServer) handle(w http.ResponseWriter, r *http.Request) {
	// Best-effort body read; test doubles need not stream.
	body := make([]byte, 0, 256)
	buf := make([]byte, 512)
	for {
		n, err := r.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	_ = r.Body.Close()

	m.mu.Lock()
	m.requests = append(m.requests, RecordedRequest{
		Method: r.Method,
		Path:   r.URL.Path,
		Query:  r.URL.RawQuery,
		Header: r.Header.Clone(),
		Body:   body,
	})
	resp, ok := m.responses[r.URL.Path]
	m.mu.Unlock()

	if !ok {
		http.NotFound(w, r)
		return
	}
	if resp.Headers != nil {
		for k, vs := range resp.Headers {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
	} else {
		w.Header().Set("Content-Type", "application/json")
	}
	status := resp.Status
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	if resp.Body != "" {
		_, _ = w.Write([]byte(resp.Body))
	}
}
