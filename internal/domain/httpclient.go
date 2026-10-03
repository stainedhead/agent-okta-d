package domain

import "net/http"

// NoRedirect returns a copy of c that never follows redirects, so a 307/308
// cannot re-send a POST body (refresh token, device code) or an Authorization
// header to another host. The 3xx response is returned to the caller. A nil c
// yields a plain client with the same policy.
func NoRedirect(c *http.Client) *http.Client {
	cp := http.Client{}
	if c != nil {
		cp = *c
	}
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &cp
}
