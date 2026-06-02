package bitwarden

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

const testUUID = "e92f4f1a-0c3d-4b2a-9f1e-2a3b4c5d6e7f"

func TestBWSResolver_ResolvesValueFromJSON(t *testing.T) {
	t.Parallel()

	fr := &fakeRunner{stdout: []byte(`{"object":"secret","id":"` + testUUID + `","key":"k","value":"sk-real","note":""}`)}
	r := &bwsResolver{runner: fr, token: "tok"}

	got, err := r.Resolve(context.Background(), "", "bw://"+testUUID)
	require.NoError(t, err)
	require.Equal(t, "sk-real", got)
	require.Equal(t, []string{"secret", "get", testUUID, "--output", "json"}, fr.gotArgs)
}

func TestBWSResolver_PassesTokenViaEnvNotArgv(t *testing.T) {
	t.Parallel()

	fr := &fakeRunner{stdout: []byte(`{"value":"sk-real"}`)}
	r := &bwsResolver{runner: fr, token: "super-secret-token"}

	_, err := r.Resolve(context.Background(), "", "bw://"+testUUID)
	require.NoError(t, err)
	require.Contains(t, fr.gotEnv, "BWS_ACCESS_TOKEN=super-secret-token")
	require.False(t, slices.Contains(fr.gotArgs, "super-secret-token"), "token must never appear in argv")
}

func TestBWSResolver_AddsServerURLFlagWhenSelfHosted(t *testing.T) {
	t.Parallel()

	fr := &fakeRunner{stdout: []byte(`{"value":"sk-real"}`)}
	r := &bwsResolver{runner: fr, token: "tok", serverURL: "https://vault.example.com"}

	_, err := r.Resolve(context.Background(), "", "bw://"+testUUID)
	require.NoError(t, err)
	require.Equal(t,
		[]string{"secret", "get", testUUID, "--output", "json", "--server-url", "https://vault.example.com"},
		fr.gotArgs)
}

func TestBWSResolver_OmitsServerURLFlagOnCloud(t *testing.T) {
	t.Parallel()

	fr := &fakeRunner{stdout: []byte(`{"value":"sk-real"}`)}
	r := &bwsResolver{runner: fr, token: "tok"}

	_, err := r.Resolve(context.Background(), "", "bw://"+testUUID)
	require.NoError(t, err)
	require.False(t, slices.Contains(fr.gotArgs, "--server-url"))
}

func TestBWSResolver_NonZeroExitFailsClosed(t *testing.T) {
	t.Parallel()

	fr := &fakeRunner{err: errors.New("exit status 1")}
	r := &bwsResolver{runner: fr, token: "tok"}

	_, err := r.Resolve(context.Background(), "", "bw://"+testUUID)
	require.Error(t, err)
}

func TestBWSResolver_GarbageJSONFailsClosed(t *testing.T) {
	t.Parallel()

	fr := &fakeRunner{stdout: []byte(`not json`)}
	r := &bwsResolver{runner: fr, token: "tok"}

	_, err := r.Resolve(context.Background(), "", "bw://"+testUUID)
	require.Error(t, err)
}

func TestBWSResolver_EmptyValueFailsClosed(t *testing.T) {
	t.Parallel()

	fr := &fakeRunner{stdout: []byte(`{"value":""}`)}
	r := &bwsResolver{runner: fr, token: "tok"}

	_, err := r.Resolve(context.Background(), "", "bw://"+testUUID)
	require.Error(t, err)
}

func TestBWSResolver_MalformedRefFailsClosedWithoutExec(t *testing.T) {
	t.Parallel()

	for name, ref := range map[string]string{
		"wrong scheme": "op://" + testUUID,
		"not a uuid":   "bw://not-a-uuid",
		"empty id":     "bw://",
		"too short":    "bw://e92f4f1a",
		"no dashes":    "bw://e92f4f1a0c3d4b2a9f1e2a3b4c5d6e7f1234", // 36 chars, hex, no separators
		"non-hex char": "bw://g92f4f1a-0c3d-4b2a-9f1e-2a3b4c5d6e7f", // 36-shaped but a non-hex digit
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fr := &fakeRunner{stdout: []byte(`{"value":"sk-real"}`)}
			r := &bwsResolver{runner: fr, token: "tok"}

			_, err := r.Resolve(context.Background(), "", ref)
			require.Error(t, err)
			require.Equal(t, 0, fr.calls, "runner must not be invoked for a malformed reference")
		})
	}
}

func TestBWSResolver_NonEmptyVaultIDFailsClosedWithoutExec(t *testing.T) {
	t.Parallel()

	fr := &fakeRunner{stdout: []byte(`{"value":"sk-real"}`)}
	r := &bwsResolver{runner: fr, token: "tok"}

	_, err := r.Resolve(context.Background(), "vault-a", "bw://"+testUUID)
	require.Error(t, err)
	require.Equal(t, 0, fr.calls, "runner must not be invoked when vaultID is set")
}

func TestBWSResolver_DoesNotLogSecretValue(t *testing.T) {
	t.Parallel()

	// Guard: the resolved value must never appear in the error returned on a
	// downstream parse-failure path. The raw-secret case is the important one:
	// encoding/json's SyntaxError quotes the first offending input byte
	// ("invalid character 'Z' ..."), so wrapping it with %w would leak a byte
	// of the secret. The fixed message must echo nothing from stdout. 'Z' is a
	// sentinel chosen to be absent from the fixed "bws output was not valid
	// json" message, so its absence proves the first byte did not leak.
	cases := map[string]string{
		"truncated json":       `{"value":"Zsecret"`,
		"raw plaintext secret": "Zsecret-not-json",
	}
	for name, stdout := range cases {
		stdout := stdout
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			fr := &fakeRunner{stdout: []byte(stdout)}
			r := &bwsResolver{runner: fr, token: "tok"}

			_, err := r.Resolve(context.Background(), "", "bw://"+testUUID)
			require.Error(t, err)
			require.NotContains(t, err.Error(), "Zsecret", "error must not leak the secret value")
			require.NotContains(t, err.Error(), "Z", "error must not echo even the first byte of stdout")
		})
	}
}
