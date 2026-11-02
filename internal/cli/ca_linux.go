//go:build linux

package cli

// caInstalledFormat reports where ca install wrote the CA. Distribution trust
// tools read only system directories, so on Linux that copy trusts nothing by
// itself and the message says what does.
const caInstalledFormat = "Wrote a copy of the CA to %s, which trusts nothing by itself.\n" +
	"Clients that honor SSL_CERT_FILE work after: eval \"$(postern bootstrap)\"\n" +
	"For other clients, add the CA to the system store:\n" +
	"https://github.com/mmartinez/postern/blob/main/docs/security.md#key-and-token-handling\n"
