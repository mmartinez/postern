package cli_test

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/ca"
)

// TestServer_SIGTERMShutsDownCleanly drives the real postern binary and
// asserts the "SIGTERM graceful shutdown within 10s" acceptance criterion.
// The runtime-level test in internal/runtime exercises the full request
// path in-process; this test's job is exclusively the signal + exit
// contract that an in-process test can't observe (the binary's actual
// process-level Wait()).
func TestServer_SIGTERMShutsDownCleanly(t *testing.T) {
	// Not Parallel — go build dominates wall-clock and the test is short.

	bin := buildPosternBinary(t)
	home := t.TempDir()
	caDir := filepath.Join(home, ".postern")

	authority, err := ca.Generate(time.Now())
	require.NoError(t, err)
	require.NoError(t, authority.Save(caDir))

	addr := freeLoopbackAddr(t)
	cmd := exec.Command(bin, "server", "--addr", addr) //nolint:gosec // test-built binary
	cmd.Env = append([]string{"HOME=" + home}, filteredEnv()...)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() {
		if cmd.ProcessState == nil || !cmd.ProcessState.Exited() {
			_ = cmd.Process.Signal(syscall.SIGKILL)
			_, _ = cmd.Process.Wait()
		}
	})

	require.NoError(t, waitForPort(addr, 5*time.Second), "server failed to bind")

	require.NoError(t, cmd.Process.Signal(syscall.SIGTERM))

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	shutdownCtx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	select {
	case err := <-exited:
		require.NoError(t, err, "SIGTERM should produce a clean exit")
	case <-shutdownCtx.Done():
		t.Fatalf("server did not shut down within 10s of SIGTERM")
	}
}

func buildPosternBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	out := filepath.Join(dir, "postern")
	build := exec.Command("go", "build", "-o", out, "./cmd/postern")
	build.Dir = findRepoRoot(t)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, output)
	}
	return out
}

// findRepoRoot walks up from the test's working dir until it finds go.mod.
// We can't use runtime.Caller paths because the test binary's working
// directory under `go test` is the package dir, and the module root may
// be several levels up.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := exec.Command("pwd").Output()
	require.NoError(t, err)
	cur := strings.TrimSpace(string(wd))
	for {
		if _, err := exec.Command("test", "-f", filepath.Join(cur, "go.mod")).Output(); err == nil {
			return cur
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			t.Fatal("repo root not found (walked above /)")
		}
		cur = parent
	}
}

// filteredEnv returns the current process environment minus HOME so the
// child gets exactly one HOME entry — the one we prepended.
func filteredEnv() []string {
	env := os.Environ()
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if strings.HasPrefix(kv, "HOME=") {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()
	require.NoError(t, l.Close())
	return addr
}

func waitForPort(addr string, budget time.Duration) error {
	deadline := time.Now().Add(budget)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("port %s not open within %v", addr, budget)
}
