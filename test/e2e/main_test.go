//go:build e2e

// Package e2e_test exercises the compiled postern binary black-box: each
// test builds the real config.yaml, runs `postern server` as a subprocess
// against local stub upstreams and IdPs, and asserts on observable HTTP
// behavior. Run with:
//
//	go test -tags=e2e ./test/e2e/...
package e2e_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// posternBin is the path of the binary built once by TestMain.
var posternBin string

func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "postern-e2e-bin-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "e2e: mktemp: %v\n", err)
		os.Exit(1)
	}
	bin := filepath.Join(tmp, "postern")

	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		fmt.Fprintln(os.Stderr, "e2e: cannot locate repo root")
		os.Exit(1)
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(thisFile), "..", ".."))

	build := exec.Command("go", "build", "-o", bin, "./cmd/postern")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "e2e: build postern: %v\n%s\n", err, out)
		os.Exit(1)
	}
	posternBin = bin

	code := m.Run()
	_ = os.RemoveAll(tmp)
	os.Exit(code)
}
