package internalhelpers

import "os"

// readSource reads a source file inside this package. Used by tests that
// need to assert source-level properties (e.g. "we still use
// crypto/subtle").
func readSource(name string) (string, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
