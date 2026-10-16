package jsmap

import "testing"

// A browser fetch() cannot use a bracketed DNS/IPv4/IPvFuture address as the
// host of an HTTP(S) URL. The Go URL parser alone is not sufficient to reject
// these forms; they must not become inferred endpoint evidence.
func TestBracketedHTTPAuthorityValidation(t *testing.T) {
	for _, raw := range []string{
		"https://[example.test]/not-an-endpoint?token=SECRET",
		"http://[127.0.0.1]/not-an-endpoint",
		"https://[v1.fe80]/not-an-endpoint",
		"https://[::1%25eth0]/not-browser-fetch",
		"//[example.test]/not-an-endpoint",
		"https://user:password@[example.test]/not-an-endpoint",
	} {
		t.Run("reject_"+raw, func(t *testing.T) {
			if got, _, _, ok := endpoint(raw); ok {
				t.Fatalf("invalid browser URL accepted as evidence: %q => %q", raw, got)
			}
		})
	}
	good := []struct {
		input, want             string
		redactQuery, redactUser bool
	}{
		{"https://[::1]/real?secret=HIDDEN", "https://[::1]/real", true, false},
		{"http://[::ffff:127.0.0.1]:8080/real", "http://[::ffff:127.0.0.1]:8080/real", false, false},
		{"//[::1]:8000/relative", "//[::1]:8000/relative", false, false},
		{"https://user:pw@example.test/real", "https://example.test/real", false, true},
		{"/static/[example.test]/path", "/static/[example.test]/path", false, false},
	}
	for _, v := range good {
		t.Run("accept_"+v.input, func(t *testing.T) {
			got, q, u, ok := endpoint(v.input)
			if !ok || got != v.want || q != v.redactQuery || u != v.redactUser {
				t.Fatalf("%q=>%q, flags (%v,%v), ok=%v; want %q, (%v,%v)", v.input, got, q, u, ok, v.want, v.redactQuery, v.redactUser)
			}
		})
	}
}
