package cli

import (
	"bytes"
	"os/user"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/mmartinez/postern/internal/approval"
)

func TestApprovalPolicyCmd(t *testing.T) {
	t.Parallel()

	alice := func() (*user.User, error) { return &user.User{Username: "alice"}, nil }
	cases := []struct {
		name    string
		goos    string
		euid    int
		wantOut string
		wantErr string
	}{
		{name: "prints the policy for the current user", goos: "linux", euid: 1000, wantOut: approval.Policy("alice")},
		{
			name:    "refuses root",
			goos:    "linux",
			euid:    0,
			wantErr: "run postern approval policy as your own user, not root, and pipe it into sudo tee " + policyPath,
		},
		{
			name:    "macOS needs no policy",
			goos:    "darwin",
			euid:    501,
			wantErr: "macOS needs no approval setup: postern asks LocalAuthentication directly",
		},
		{
			name:    "unsupported platform",
			goos:    "windows",
			euid:    1000,
			wantErr: "approval is not supported on windows",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cmd := newApprovalPolicyCmd(tc.goos, func() int { return tc.euid }, alice)
			cmd.SilenceUsage, cmd.SilenceErrors = true, true
			var out bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetArgs(nil)
			err := cmd.Execute()
			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
				require.Empty(t, out.String())
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.wantOut, out.String())
		})
	}
}
