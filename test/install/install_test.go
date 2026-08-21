// Package install_test drives the repo-root install.sh against a fake GitHub
// release served over httptest. It shells out to the script (no postern code is
// imported) and asserts arch handling, checksum verification, and the install
// location — the behavior a user hits running the one-liner installer.
package install_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// installScript returns the absolute path to the repo-root install.sh,
// resolved from this test file's location so the test is CWD-independent.
func installScript(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	require.True(t, ok)
	p := filepath.Join(filepath.Dir(thisFile), "..", "..", "install.sh")
	abs, err := filepath.Abs(p)
	require.NoError(t, err)
	return abs
}

// fakeTarball returns a gzipped tar containing a single executable file named
// "postern" with the given script body, plus its hex sha256.
func fakeTarball(t *testing.T, body string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	require.NoError(t, tw.WriteHeader(&tar.Header{
		Name: "postern",
		Mode: 0o755,
		Size: int64(len(body)),
	}))
	_, err := tw.Write([]byte(body))
	require.NoError(t, err)
	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

// serveRelease starts an httptest server that serves the asset and a
// checksums.txt under /<tag>/. checksumOverride, if non-empty, replaces the
// real digest so a mismatch can be exercised.
func serveRelease(t *testing.T, tag, asset string, tarball []byte, sum, checksumOverride string) *httptest.Server {
	t.Helper()
	digest := sum
	if checksumOverride != "" {
		digest = checksumOverride
	}
	checksums := fmt.Sprintf("%s  %s\n", digest, asset)

	mux := http.NewServeMux()
	mux.HandleFunc("/"+tag+"/"+asset, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(tarball)
	})
	mux.HandleFunc("/"+tag+"/checksums.txt", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(checksums))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// runInstall executes install.sh with the given extra env and returns combined
// stdout, stderr, and the run error.
func runInstall(t *testing.T, env map[string]string) (string, string, error) {
	t.Helper()
	// Absolute interpreter path: one test runs with a hermetic PATH that
	// deliberately excludes everything but the tools install.sh needs.
	cmd := exec.Command("/bin/sh", installScript(t))
	cmd.Env = append(os.Environ(), "POSTERN_OS=linux")
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func TestInstallHappyPath(t *testing.T) {
	t.Parallel()
	const tag, ver = "v1.2.3", "1.2.3"
	asset := "postern_" + ver + "_linux_amd64.tar.gz"
	tarball, sum := fakeTarball(t, "#!/bin/sh\necho 'postern fake "+ver+"'\n")
	srv := serveRelease(t, tag, asset, tarball, sum, "")
	installDir := t.TempDir()

	_, stderr, err := runInstall(t, map[string]string{
		"POSTERN_ARCH":        "amd64",
		"POSTERN_VERSION":     tag,
		"POSTERN_BASE_URL":    srv.URL,
		"POSTERN_INSTALL_DIR": installDir,
	})
	require.NoError(t, err, "install.sh failed; stderr:\n%s", stderr)

	binPath := filepath.Join(installDir, "postern")
	info, statErr := os.Stat(binPath)
	require.NoError(t, statErr, "binary not installed")
	require.Equal(t, os.FileMode(0o755), info.Mode().Perm(), "binary not executable")

	out, runErr := exec.Command(binPath).Output()
	require.NoError(t, runErr)
	require.Contains(t, string(out), "postern fake "+ver)
}

func TestInstallChecksumMismatchAborts(t *testing.T) {
	t.Parallel()
	const tag, ver = "v1.2.3", "1.2.3"
	asset := "postern_" + ver + "_linux_amd64.tar.gz"
	tarball, _ := fakeTarball(t, "#!/bin/sh\necho hi\n")
	// Serve a checksums.txt whose digest does not match the tarball.
	bogus := strings.Repeat("0", 64)
	srv := serveRelease(t, tag, asset, tarball, "", bogus)
	installDir := t.TempDir()

	_, stderr, err := runInstall(t, map[string]string{
		"POSTERN_ARCH":        "amd64",
		"POSTERN_VERSION":     tag,
		"POSTERN_BASE_URL":    srv.URL,
		"POSTERN_INSTALL_DIR": installDir,
	})
	require.Error(t, err, "install.sh should fail on checksum mismatch")
	require.Contains(t, strings.ToLower(stderr), "checksum")
	_, statErr := os.Stat(filepath.Join(installDir, "postern"))
	require.ErrorIs(t, statErr, os.ErrNotExist, "binary must not be installed on checksum failure")
}

func TestInstallUnsupportedArchAborts(t *testing.T) {
	t.Parallel()
	installDir := t.TempDir()
	_, stderr, err := runInstall(t, map[string]string{
		"POSTERN_ARCH":        "mips",
		"POSTERN_VERSION":     "v1.2.3",
		"POSTERN_BASE_URL":    "http://127.0.0.1:0", // must never be reached
		"POSTERN_INSTALL_DIR": installDir,
	})
	require.Error(t, err, "install.sh should reject an unsupported arch")
	require.Contains(t, strings.ToLower(stderr), "unsupported architecture")
	_, statErr := os.Stat(filepath.Join(installDir, "postern"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

// TestInstallDarwinHappyPath pins the darwin asset naming against the
// goreleaser name_template (postern_<ver>_<os>_<arch>.tar.gz) for both new
// darwin targets, and proves the script end-to-end on the darwin path.
func TestInstallDarwinHappyPath(t *testing.T) {
	t.Parallel()
	for _, arch := range []string{"amd64", "arm64"} {
		t.Run(arch, func(t *testing.T) {
			t.Parallel()
			const tag, ver = "v1.2.3", "1.2.3"
			asset := "postern_" + ver + "_darwin_" + arch + ".tar.gz"
			tarball, sum := fakeTarball(t, "#!/bin/sh\necho 'postern fake "+ver+"'\n")
			srv := serveRelease(t, tag, asset, tarball, sum, "")
			installDir := t.TempDir()

			_, stderr, err := runInstall(t, map[string]string{
				"POSTERN_OS":          "darwin",
				"POSTERN_ARCH":        arch,
				"POSTERN_VERSION":     tag,
				"POSTERN_BASE_URL":    srv.URL,
				"POSTERN_INSTALL_DIR": installDir,
			})
			require.NoError(t, err, "install.sh failed; stderr:\n%s", stderr)

			out, runErr := exec.Command(filepath.Join(installDir, "postern")).Output()
			require.NoError(t, runErr)
			require.Contains(t, string(out), "postern fake "+ver)
		})
	}
}

func TestInstallUnsupportedOSAborts(t *testing.T) {
	t.Parallel()
	installDir := t.TempDir()
	_, stderr, err := runInstall(t, map[string]string{
		"POSTERN_OS":          "windows",
		"POSTERN_ARCH":        "amd64",
		"POSTERN_VERSION":     "v1.2.3",
		"POSTERN_BASE_URL":    "http://127.0.0.1:0", // must never be reached
		"POSTERN_INSTALL_DIR": installDir,
	})
	require.Error(t, err, "install.sh should reject an unsupported OS")
	require.Contains(t, strings.ToLower(stderr), "unsupported os")
	_, statErr := os.Stat(filepath.Join(installDir, "postern"))
	require.ErrorIs(t, statErr, os.ErrNotExist)
}

// TestInstallShasumFallbackOnDarwin exercises the checksum-tool fallback a
// stock macOS host hits: no GNU sha256sum, only shasum -a 256. The test PATH
// contains exactly the external tools install.sh needs, sha256sum excluded.
func TestInstallShasumFallbackOnDarwin(t *testing.T) {
	if _, err := exec.LookPath("shasum"); err != nil {
		t.Skip("shasum not available on this host")
	}
	bin := t.TempDir()
	for _, tool := range []string{"mktemp", "rm", "awk", "tar", "mkdir", "install", "shasum", "curl", "gzip"} {
		path, err := exec.LookPath(tool)
		require.NoError(t, err, "missing %s for hermetic PATH", tool)
		require.NoError(t, os.Symlink(path, filepath.Join(bin, tool)))
	}
	// t.Setenv forbids t.Parallel; env is inherited by the script below.
	t.Setenv("PATH", bin)

	const tag, ver = "v1.2.3", "1.2.3"
	asset := "postern_" + ver + "_darwin_arm64.tar.gz"
	tarball, sum := fakeTarball(t, "#!/bin/sh\necho 'postern fake "+ver+"'\n")
	srv := serveRelease(t, tag, asset, tarball, sum, "")
	installDir := t.TempDir()

	_, stderr, err := runInstall(t, map[string]string{
		"POSTERN_OS":          "darwin",
		"POSTERN_ARCH":        "arm64",
		"POSTERN_VERSION":     tag,
		"POSTERN_BASE_URL":    srv.URL,
		"POSTERN_INSTALL_DIR": installDir,
	})
	require.NoError(t, err, "install.sh failed; stderr:\n%s", stderr)
	_, statErr := os.Stat(filepath.Join(installDir, "postern"))
	require.NoError(t, statErr)
}
