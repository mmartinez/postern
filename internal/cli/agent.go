package cli

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/mmartinez/postern/internal/config"
	"github.com/mmartinez/postern/internal/identity"
)

// NewAgentCmd constructs the named, in-memory credential launcher and inventory.
func NewAgentCmd() *cobra.Command {
	root := &cobra.Command{Use: "agent", Short: "Enroll and launch authenticated proxy clients", SilenceUsage: true, SilenceErrors: true}
	for _, action := range []string{"add", "rotate", "remove", "list"} {
		usage := action + " [NAME] [flags]"
		if action == "add" || action == "rotate" {
			usage = action + " NAME [flags] --exec PROGRAM [ARGS...]"
		}
		cmd := &cobra.Command{Use: usage, DisableFlagParsing: true}
		cmd.Flags().String("config", "", "Config path (default: ~/.postern/config.yaml)")
		cmd.Flags().String("enrollment-out", "", "Write hash-only enrollment artifact")
		cmd.Flags().String("proxy", "", "Proxy URL without credentials")
		cmd.Flags().String("ca", "", "Public CA bundle for both TLS hops")
		cmd.RunE = func(cmd *cobra.Command, args []string) error { return runAgent(cmd, action, args) }
		root.AddCommand(cmd)
	}
	return root
}

func runAgent(cmd *cobra.Command, action string, args []string) error {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		return cmd.Help()
	}
	var recipient []string
	for i, a := range args {
		if a == "--exec" {
			recipient, args = args[i+1:], args[:i]
			break
		}
	}
	if err := cmd.Flags().Parse(args); err != nil {
		return errors.New("invalid agent command flags")
	}
	args = cmd.Flags().Args()
	if action != "list" && (len(args) != 1 || !identity.ValidName(args[0])) {
		return errors.New("one valid agent name is required")
	}
	if action == "list" && len(args) != 0 {
		return errors.New("list takes no agent name")
	}
	if (action == "add" || action == "rotate") && len(recipient) == 0 {
		return errors.New("select a recipient with --exec program before enrollment")
	}
	path, _ := cmd.Flags().GetString("config")
	if path == "" {
		path = config.DefaultPath()
	}
	out, _ := cmd.Flags().GetString("enrollment-out")
	proxyURL, _ := cmd.Flags().GetString("proxy")
	caPath, _ := cmd.Flags().GetString("ca")
	if caPath != "" {
		if _, err := os.Stat(caPath); err != nil {
			return errors.New("public CA bundle is not readable")
		}
	}
	if out != "" && (cmd.Flags().Changed("config") || action != "add" && action != "rotate") {
		return errors.New("enrollment output is mutually exclusive with live config mutation")
	}
	var cfg *config.Config
	var err error
	if out == "" {
		cfg, err = config.LoadForCLI(path, true)
		if err != nil {
			return err
		}
		if action == "list" {
			for _, a := range cfg.Agents {
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), a.Name); err != nil {
					return err
				}
			}
			return nil
		}
		if cfg.Proxy.ClientAuth != "required" {
			return errors.New("agent enrollment requires proxy.client_auth: required")
		}
		if proxyURL == "" {
			proxyURL = "http://" + cfg.Proxy.Listen
			if cfg.Proxy.TLS != nil {
				_, port, _ := net.SplitHostPort(cfg.Proxy.Listen)
				proxyURL = "https://" + net.JoinHostPort(cfg.Proxy.TLS.Names[0], port)
			}
		}
	}
	name := args[0]
	if action == "remove" {
		return editAgentConfig(path, action, config.Agent{Name: name})
	}
	u, err := url.Parse(proxyURL)
	if err != nil || u == nil || u.User != nil || u.Hostname() == "" || u.Scheme != "http" && u.Scheme != "https" || u.RawQuery != "" || u.Fragment != "" || u.Path != "" && u.Path != "/" {
		return errors.New("a proxy URL without userinfo, query, or path is required")
	}
	key, verifier, err := identity.Generate()
	if err != nil {
		return err
	}
	agent := config.Agent{Name: name, KeySHA256: verifier}
	if out != "" {
		if err := writeEnrollment(out, agent); err != nil {
			return err
		}
	} else if err := editAgentConfig(path, action, agent); err != nil {
		return err
	}
	if out == "" {
		if err := waitForEnrollment(cmd.Context(), u, name, key, caPath); err != nil {
			return fmt.Errorf("agent %s: %w", name, err)
		}
	}
	u.User = url.UserPassword(name, key)
	child := exec.CommandContext(cmd.Context(), recipient[0], recipient[1:]...) //nolint:gosec // explicitly selected recipient, never a shell
	child.Env = launcherEnv(os.Environ(), u.String())
	if caPath != "" {
		for _, variable := range []string{"SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE"} {
			child.Env = append(child.Env, variable+"="+caPath)
		}
	}
	child.Stdin, child.Stdout, child.Stderr = cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr()
	if err := child.Run(); err != nil {
		return fmt.Errorf("agent %s: client launch or execution failed", name)
	}
	return nil
}

func launcherEnv(base []string, proxyURL string) []string {
	out := make([]string, 0, len(base)+4)
	for _, entry := range base {
		key, _, _ := strings.Cut(entry, "=")
		switch strings.ToUpper(key) {
		case "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY":
			continue
		}
		out = append(out, entry)
	}
	return append(out, "HTTP_PROXY="+proxyURL, "HTTPS_PROXY="+proxyURL, "http_proxy="+proxyURL, "https_proxy="+proxyURL, "NO_PROXY=", "no_proxy=", "NODE_USE_ENV_PROXY=1")
}

func writeEnrollment(path string, agent config.Agent) error {
	raw, err := yaml.Marshal(struct {
		Agents []config.Agent `yaml:"agents"`
	}{[]config.Agent{agent}})
	if err != nil {
		return errors.New("encode enrollment failed")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // operator-selected path
	if err != nil {
		return errors.New("create enrollment artifact failed")
	}
	_, writeErr := f.Write(raw)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		return errors.New("write enrollment artifact failed")
	}
	return nil
}

func editAgentConfig(path, action string, agent config.Agent) error {
	lock, err := os.OpenFile(path+".enrollment-lock", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // cooperative editor lock
	if err != nil {
		if errors.Is(err, os.ErrPermission) {
			return errors.New("config directory is read-only; install enrollment through the protected operator config workflow")
		}
		return errors.New("config is being edited; retry after the other editor finishes")
	}
	defer func() { _ = lock.Close(); _ = os.Remove(lock.Name()) }()
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0o222 == 0 {
		return errors.New("config is read-only; install enrollment through the protected operator config workflow")
	}
	before, err := os.ReadFile(path) //nolint:gosec // operator-selected config
	if err != nil {
		return errors.New("read agent config failed")
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(before, &doc); err != nil {
		return errors.New("parse agent config failed")
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return errors.New("config must be a YAML mapping")
	}
	root := doc.Content[0]
	var agents *yaml.Node
	for i := 0; i < len(root.Content); i += 2 {
		if root.Content[i].Value == "agents" {
			agents = root.Content[i+1]
		}
	}
	if agents == nil {
		agents = &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		root.Content = append(root.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "agents"}, agents)
	}
	index := -1
	for i, n := range agents.Content {
		var existing config.Agent
		if err := n.Decode(&existing); err != nil {
			return errors.New("invalid agent config")
		}
		if existing.Name == agent.Name {
			index = i
		}
	}
	if action == "add" && index >= 0 {
		return errors.New("agent already enrolled; use rotate")
	}
	if action != "add" && index < 0 {
		return errors.New("agent is not enrolled")
	}
	if action == "remove" {
		agents.Content = append(agents.Content[:index], agents.Content[index+1:]...)
	} else {
		var node yaml.Node
		if err := node.Encode(agent); err != nil {
			return errors.New("encode agent failed")
		}
		if index < 0 {
			agents.Content = append(agents.Content, &node)
		} else {
			entry := agents.Content[index]
			for i := 0; i < len(entry.Content); i += 2 {
				if entry.Content[i].Value == "key_sha256" {
					entry.Content[i+1].Value = agent.KeySHA256
				}
			}
		}
	}
	raw, err := yaml.Marshal(&doc)
	if err != nil {
		return errors.New("encode agent config failed")
	}
	_, lints, err := config.LoadAndValidate(bytes.NewReader(raw))
	if err != nil {
		return errors.New("edited config is invalid")
	}
	for _, l := range lints {
		if l.Severity == config.SeverityError {
			return errors.New("edited config is invalid; run config validate")
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".enrollment-*")
	if err != nil {
		return errors.New("create atomic config update failed")
	}
	defer func() { _ = tmp.Close(); _ = os.Remove(tmp.Name()) }()
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		return errors.New("set config permissions failed")
	}
	if _, err := tmp.Write(raw); err != nil {
		return errors.New("write config update failed")
	}
	if err := tmp.Sync(); err != nil {
		return errors.New("sync config update failed")
	}
	if err := tmp.Close(); err != nil {
		return errors.New("close config update failed")
	}
	current, err := os.ReadFile(path) //nolint:gosec // concurrent edit check
	if err != nil || !bytes.Equal(current, before) {
		return errors.New("config changed concurrently; retry")
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return errors.New("replace config failed; install enrollment through the protected operator config workflow")
	}
	return nil
}
