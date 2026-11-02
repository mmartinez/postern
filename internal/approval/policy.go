// Package approval implements the broker's Approver with the operating
// system's authentication dialog, and renders the policy that dialog needs.
package approval

import (
	"encoding/xml"
	"strings"
)

// ActionID is the polkit action postern asks the user to authorize.
const ActionID = "dev.postern.authorize-secret"

const policyTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <vendor>postern</vendor>
  <action id="` + ActionID + `">
    <description>Send a credential through postern</description>
    <message>postern is trying to send a credential to an API.</message>
    <defaults>
      <allow_any>auth_self</allow_any>
      <allow_inactive>auth_self</allow_inactive>
      <allow_active>auth_self</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.owner">unix-user:USER</annotate>
  </action>
</policyconfig>
`

// Policy renders the polkit action file for ActionID. user owns the action:
// polkit only accepts the dialog text postern passes from a non-root caller
// when the action names that caller's user as its owner.
func Policy(user string) string {
	var escaped strings.Builder
	_ = xml.EscapeText(&escaped, []byte(user))
	return strings.Replace(policyTemplate, "unix-user:USER", "unix-user:"+escaped.String(), 1)
}
