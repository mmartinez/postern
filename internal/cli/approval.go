package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"

	"github.com/spf13/cobra"

	"github.com/mmartinez/postern/internal/approval"
)

// policyPath is where polkit reads action files from.
const policyPath = "/usr/share/polkit-1/actions/dev.postern.policy"

// NewApprovalCmd builds `postern approval`, the parent for the setup that
// approval prompts need.
func NewApprovalCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "approval",
		Short: "Set up OS approval prompts for rules that declare approval",
	}
	cmd.AddCommand(newApprovalPolicyCmd(os.Geteuid, user.Current))
	return cmd
}

func newApprovalPolicyCmd(euid func() int, current func() (*user.User, error)) *cobra.Command {
	return &cobra.Command{
		Use:   "policy",
		Short: "Print the polkit action file approval prompts need (Linux)",
		Long: "Print the polkit action file that lets postern show approval\n" +
			"prompts. Run it as the user who runs postern, then install it:\n\n" +
			"  postern approval policy |\n" +
			"    sudo tee " + policyPath,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// The policy names its owner, and only the owner may set the
			// dialog text, so it must be rendered for the unprivileged user.
			if euid() == 0 {
				return errors.New("run postern approval policy as your own user, not root, and pipe it into sudo tee " + policyPath)
			}
			u, err := current()
			if err != nil {
				return fmt.Errorf("look up current user: %w", err)
			}
			_, err = io.WriteString(cmd.OutOrStdout(), approval.Policy(u.Username))
			return err
		},
	}
}
