package broker

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/identity"
)

func TestReloadPublishesIdentityAndRulesTogether(t *testing.T) {
	t.Parallel()
	key, hash, err := identity.Generate()
	require.NoError(t, err)
	e := NewEngine(nil)
	require.NoError(t, e.Publish(nil, []config.Agent{{Name: "agent", KeySHA256: hash}}))
	p := e.Authenticate("agent", key)
	baseline := &Baseline{Proxy: config.Proxy{ClientAuth: "required", OnNoMatch: config.OnNoMatchBlock}}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	version := NewVersionCounter()
	applyReload(e, config.Event{New: &config.Config{Proxy: baseline.Proxy}}, logger, baseline, version)
	require.False(t, e.Current(p))
	require.Nil(t, e.Authenticate("agent", key))
	require.EqualValues(t, 2, version.Load())
	applyReload(e, config.Event{New: &config.Config{Agents: []config.Agent{{Name: "invalid.name", KeySHA256: hash}}}}, logger, baseline, version)
	require.EqualValues(t, 2, version.Load())
	require.Nil(t, e.Authenticate("agent", key))
}
