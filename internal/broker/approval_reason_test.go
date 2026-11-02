package broker

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestApprovalReason(t *testing.T) {
	t.Parallel()

	long := "/" + strings.Repeat("a", 200)
	cases := []struct {
		name   string
		method string
		url    string
		route  string
		want   string
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			u, err := url.Parse(tc.url)
			require.NoError(t, err)
			req := &http.Request{Method: tc.method, URL: u}
			require.Equal(t, tc.want, approvalReason(req, "op://V/I/f", tc.route))
		})
	}
}
