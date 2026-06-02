package cli_test

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/cli"
	"github.com/mmartinez/postern/internal/credstore"
	"github.com/mmartinez/postern/internal/token"
)

func TestServerCmd_ErrorsWhenCAMissing(t *testing.T) {
	t.Parallel()
	caDir := filepath.Join(t.TempDir(), "no-such-ca")

	cmd := cli.NewServerCmd(caDir, credstore.Default(), token.NewMemoryStore())
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // pre-cancelled so Run() returns immediately if it ever gets there
	cmd.SetContext(ctx)

	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{})

	err := cmd.Execute()
	require.Error(t, err, "missing CA must surface as an error")
	require.Contains(t, err.Error(), "postern ca install",
		"error must guide the user to the fix")
}
