package broker_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/broker"
	"github.com/mmartinez/postern/internal/config"
)

// mapResolver resolves each ref to a distinct value and counts calls, so an
// oauth1 test can assert all four credential refs were resolved and can fail one
// of them on demand.
type mapResolver struct {
	mu    sync.Mutex
	vals  map[string]string
	calls map[string]int
	errOn string
}

func (m *mapResolver) Resolve(_ context.Context, _, ref string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls[ref]++
	if ref == m.errOn {
		return "", errors.New("resolve failed")
	}
	return m.vals[ref], nil
}

func oauth1Refs() broker.OAuth1Refs {
	return broker.OAuth1Refs{
		ConsumerKeyRef:    "op://v/ck",
		ConsumerSecretRef: "op://v/cs",
		TokenRef:          "op://v/tk",
		TokenSecretRef:    "op://v/ts",
	}
}

func oauth1Engine() *broker.Engine {
	return broker.NewEngine([]broker.Rule{{
		Host:      "api.example.com",
		Injection: broker.InjectSpec{Type: broker.InjectOAuth1, OAuth1: oauth1Refs()},
	}})
}

func discardLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestHook_OAuth1SignsAndSetsAuthorization(t *testing.T) {
	t.Parallel()
	res := &mapResolver{
		vals:  map[string]string{"op://v/ck": "ckv", "op://v/cs": "csv", "op://v/tk": "tkv", "op://v/ts": "tsv"},
		calls: map[string]int{},
	}
	hook := broker.Hook(oauth1Engine(), res, config.OnNoMatchPassthrough, 0, discardLog()) //nolint:bodyclose // closure

	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/1.1/statuses/update.json?include_entities=true", strings.NewReader("status=hi"))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	require.Nil(t, hook(req), "a complete oauth1 signing must not short-circuit") //nolint:bodyclose // nil on success

	auth := req.Header.Get("Authorization")
	require.True(t, strings.HasPrefix(auth, "OAuth "), "authorization must use the OAuth scheme")
	require.Contains(t, auth, "oauth_signature=")
	require.Contains(t, auth, `oauth_consumer_key="ckv"`)
	require.Equal(t, 1, res.calls["op://v/ck"], "consumer key ref must be resolved once")
	require.Equal(t, 1, res.calls["op://v/ts"], "token secret ref must be resolved once")

	body, err := io.ReadAll(req.Body)
	require.NoError(t, err)
	require.Equal(t, "status=hi", string(body), "the form body must be preserved for the upstream")
}

func TestHook_OAuth1FailsClosedOnRefError(t *testing.T) {
	t.Parallel()
	res := &mapResolver{
		vals:  map[string]string{"op://v/ck": "ckv", "op://v/cs": "csv", "op://v/tk": "tkv", "op://v/ts": "tsv"},
		calls: map[string]int{},
		errOn: "op://v/ts",
	}
	hook := broker.Hook(oauth1Engine(), res, config.OnNoMatchPassthrough, 0, discardLog()) //nolint:bodyclose // closure

	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/x", nil)
	require.NoError(t, err)

	resp := hook(req)
	require.NotNil(t, resp, "a failed ref resolution must short-circuit")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	require.Empty(t, req.Header.Get("Authorization"), "no signature must be set on failure")
}

func TestHook_OAuth1FailsClosedOnEmptyCredential(t *testing.T) {
	t.Parallel()
	res := &mapResolver{
		vals:  map[string]string{"op://v/ck": "ckv", "op://v/cs": "", "op://v/tk": "tkv", "op://v/ts": "tsv"},
		calls: map[string]int{},
	}
	hook := broker.Hook(oauth1Engine(), res, config.OnNoMatchPassthrough, 0, discardLog()) //nolint:bodyclose // closure

	req, err := http.NewRequest(http.MethodPost, "https://api.example.com/x", nil)
	require.NoError(t, err)

	resp := hook(req)
	require.NotNil(t, resp)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	require.Empty(t, req.Header.Get("Authorization"))
}
