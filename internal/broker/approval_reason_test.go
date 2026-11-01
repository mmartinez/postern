package broker

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
)

func TestApprovalReason(t *testing.T) {
	t.Parallel()

	long := "/" + strings.Repeat("a", 200)
	cases := []struct {
		name     string
		method   string
		override string
		url      string
		route    string
		want     string
	}{
		{
			name:   "any client, query and port dropped",
			method: http.MethodPost,
			url:    "https://api.example.com:443/v1/cards?token=secret",
			want:   "send op://V/I/f to POST api.example.com/v1/cards for any client",
		},
		{
			name:   "named agent",
			method: http.MethodGet,
			url:    "https://api.example.com/v1/x",
			route:  "max",
			want:   "send op://V/I/f to GET api.example.com/v1/x for agent max",
		},
		{
			name:   "path escaped, trailing dot canonicalized",
			method: http.MethodGet,
			url:    "https://api.example.com./a%20b/%C3%BC",
			want:   "send op://V/I/f to GET api.example.com/a%20b/%C3%BC for any client",
		},
		{
			name:   "control and non-ASCII bytes mapped",
			method: "GET\x1b[2J",
			url:    "https://api.ex\u00e4mple.com/x",
			want:   "send op://V/I/f to GET?[2J api.ex??mple.com/x for any client",
		},
		{
			name:   "request line cut at 120 characters",
			method: http.MethodGet,
			url:    "https://api.example.com" + long,
			want:   "send op://V/I/f to GET api.example.com/" + strings.Repeat("a", 119-len("GET api.example.com/")) + "… for any client",
		},
		{
			name:     "method override shown",
			method:   http.MethodGet,
			override: "DELETE",
			url:      "https://api.example.com/v1/x",
			want:     "send op://V/I/f to GET as DELETE api.example.com/v1/x for any client",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			u, err := url.Parse(tc.url)
			require.NoError(t, err)
			req := &http.Request{Method: tc.method, URL: u, Header: http.Header{}}
			if tc.override != "" {
				req.Header.Set("X-HTTP-Method-Override", tc.override)
			}
			require.Equal(t, tc.want, approvalReason(req, "op://V/I/f", tc.route))
		})
	}
}

func TestGrantReason(t *testing.T) {
	t.Parallel()

	bare := func(ttl time.Duration) Rule {
		return Rule{Host: "*.example.com", Approval: &config.Approval{TTL: ttl}}
	}
	cases := []struct {
		name  string
		rule  Rule
		route string
		want  string
	}{
		{
			name: "routed rule with methods and paths",
			rule: Rule{
				Host:     "api.example.com",
				Methods:  []string{http.MethodGet, http.MethodPost},
				Paths:    []string{"/v1/cards", "/v1/users"},
				Approval: &config.Approval{TTL: 10 * time.Minute},
			},
			route: "max",
			want:  "let agent max use op://V/I/f for GET/POST requests to api.example.com on paths starting with /v1/cards, /v1/users for 10m (first request: POST api.example.com/v1/cards)",
		},
		{
			name: "approval methods narrow the rule's",
			rule: Rule{
				Host:     "api.example.com",
				Methods:  []string{http.MethodGet, http.MethodPost},
				Approval: &config.Approval{TTL: 10 * time.Minute, Methods: []string{http.MethodPost}},
			},
			want: "let any client use op://V/I/f for POST or method-override requests to api.example.com on any path for 10m (first request: POST api.example.com/v1/cards)",
		},
		{
			name: "bare rule",
			rule: bare(90 * time.Minute),
			want: "let any client use op://V/I/f for all requests to *.example.com on any path for 1h30m (first request: POST api.example.com/v1/cards)",
		},
		{
			name: "seconds only",
			rule: bare(45 * time.Second),
			want: "let any client use op://V/I/f for all requests to *.example.com on any path for 45s (first request: POST api.example.com/v1/cards)",
		},
		{
			name: "whole hours",
			rule: bare(time.Hour),
			want: "let any client use op://V/I/f for all requests to *.example.com on any path for 1h (first request: POST api.example.com/v1/cards)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			u, err := url.Parse("https://api.example.com:443/v1/cards?token=secret")
			require.NoError(t, err)
			req := &http.Request{Method: http.MethodPost, URL: u}
			require.Equal(t, tc.want, grantReason(req, tc.rule, tc.route, "op://V/I/f"))
		})
	}
}
