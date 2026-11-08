package cli_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/cli"
)

const fixtureSecret = "fixture-secret-value-do-not-leak"

// fakeSecretStore records values by ref; set/rm errors are injectable.
type fakeSecretStore struct {
	values map[string]string
	err    error
}

func (f *fakeSecretStore) SetSecret(_ context.Context, ref, value string) error {
	if f.err != nil {
		return f.err
	}
	f.values[ref] = value
	return nil
}

func (f *fakeSecretStore) RemoveSecret(_ context.Context, ref string) error {
	if f.err != nil {
		return f.err
	}
	delete(f.values, ref)
	return nil
}

func runSecretCmd(t *testing.T, store cli.SecretStore, stdin string, args ...string) (string, string, error) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cmd := cli.NewSecretCmd(store)
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetIn(strings.NewReader(stdin))
	cmd.SetArgs(args)
	err := cmd.Execute()
	return stdout.String(), stderr.String(), err
}

func TestSecretSetStdin(t *testing.T) {
	t.Parallel()
	store := &fakeSecretStore{values: map[string]string{}}

	stdout, stderr, err := runSecretCmd(t, store, fixtureSecret+"\n", "set", "keychain://anthropic", "--stdin")
	require.NoError(t, err)
	require.Equal(t, fixtureSecret, store.values["keychain://anthropic"], "trailing newline must be trimmed")
	require.Contains(t, stdout, "Stored keychain://anthropic")
	require.NotContains(t, stdout+stderr, fixtureSecret, "the value must never be printed")
}

func TestSecretSetFromEnv(t *testing.T) {
	// No t.Parallel: t.Setenv requires a serial test.
	t.Setenv("POSTERN_TEST_SECRET", fixtureSecret)
	store := &fakeSecretStore{values: map[string]string{}}

	stdout, _, err := runSecretCmd(t, store, "", "set", "keychain://anthropic", "--from-env", "POSTERN_TEST_SECRET")
	require.NoError(t, err)
	require.Equal(t, fixtureSecret, store.values["keychain://anthropic"])
	require.NotContains(t, stdout, fixtureSecret)
}

func TestSecretSetInputErrors(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		stdin   string
		args    []string
		wantErr string
	}{
		{name: "both sources", stdin: fixtureSecret, args: []string{"set", "keychain://a", "--stdin", "--from-env", "X"}, wantErr: "mutually exclusive"},
		{name: "no source off a terminal", args: []string{"set", "keychain://a"}, wantErr: "specify --stdin or --from-env VAR"},
		{name: "empty stdin", stdin: "\n", args: []string{"set", "keychain://a", "--stdin"}, wantErr: "stdin is empty"},
		{name: "missing ref", stdin: fixtureSecret, args: []string{"set", "--stdin"}, wantErr: "accepts 1 arg"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := &fakeSecretStore{values: map[string]string{}}
			_, _, err := runSecretCmd(t, store, tc.stdin, tc.args...)
			require.ErrorContains(t, err, tc.wantErr)
			require.Empty(t, store.values)
		})
	}
}

func TestSecretSetStoreErrorDoesNotLeakValue(t *testing.T) {
	t.Parallel()
	store := &fakeSecretStore{values: map[string]string{}, err: errors.New("no OS secret store available")}

	stdout, stderr, err := runSecretCmd(t, store, fixtureSecret, "set", "keychain://anthropic", "--stdin")
	require.ErrorContains(t, err, "store keychain://anthropic: no OS secret store available")
	require.NotContains(t, stdout+stderr+err.Error(), fixtureSecret)
}

func TestSecretRm(t *testing.T) {
	t.Parallel()
	store := &fakeSecretStore{values: map[string]string{"keychain://anthropic": fixtureSecret}}

	stdout, _, err := runSecretCmd(t, store, "", "rm", "keychain://anthropic")
	require.NoError(t, err)
	require.Empty(t, store.values)
	require.Contains(t, stdout, "Removed keychain://anthropic")
}
