package approval

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPolicy(t *testing.T) {
	t.Parallel()

	var doc struct {
		Vendor string `xml:"vendor"`
		Action struct {
			ID       string `xml:"id,attr"`
			Defaults struct {
				Any      string `xml:"allow_any"`
				Inactive string `xml:"allow_inactive"`
				Active   string `xml:"allow_active"`
			} `xml:"defaults"`
			Annotate []struct {
				Key   string `xml:"key,attr"`
				Value string `xml:",chardata"`
			} `xml:"annotate"`
		} `xml:"action"`
	}
	dec := xml.NewDecoder(strings.NewReader(Policy(`a&b<c>"d`)))
	dec.Strict = true
	require.NoError(t, dec.Decode(&doc))

	require.Equal(t, "postern", doc.Vendor)
	require.Equal(t, ActionID, doc.Action.ID)
	require.Equal(t, "auth_self", doc.Action.Defaults.Any)
	require.Equal(t, "auth_self", doc.Action.Defaults.Inactive)
	require.Equal(t, "auth_self", doc.Action.Defaults.Active)
	require.Len(t, doc.Action.Annotate, 1)
	require.Equal(t, "org.freedesktop.policykit.owner", doc.Action.Annotate[0].Key)
	require.Equal(t, `unix-user:a&b<c>"d`, doc.Action.Annotate[0].Value, "the user name must survive XML escaping")
}
