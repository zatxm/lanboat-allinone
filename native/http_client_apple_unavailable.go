//go:build !darwin || !cgo

package native

import "errors"

func newAppleHTTPTransport(*Runtime, HTTPClientOptions, RuleSet) (httpClientTransport, error) {
	return nil, errors.New("Apple NSURLSession engine requires a native macOS build with CGO_ENABLED=1")
}
