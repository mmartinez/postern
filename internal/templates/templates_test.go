package templates

import (
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestLookupKnownTemplates(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		want Template
	}{
		{
			name: "anthropic",
			want: Template{
				Name:       "anthropic",
				Host:       "api.anthropic.com",
				InjectType: "header",
				HeaderName: "x-api-key",
				Template:   "{{ CREDENTIAL }}",
			},
		},
		{
			name: "openai",
			want: Template{
				Name:       "openai",
				Host:       "api.openai.com",
				InjectType: "header",
				HeaderName: "authorization",
				Template:   "Bearer {{ CREDENTIAL }}",
			},
		},
		{
			name: "github",
			want: Template{
				Name:       "github",
				Host:       "api.github.com",
				InjectType: "header",
				HeaderName: "authorization",
				Template:   "Bearer {{ CREDENTIAL }}",
			},
		},
		{
			name: "stripe",
			want: Template{
				Name:       "stripe",
				Host:       "api.stripe.com",
				InjectType: "header",
				HeaderName: "authorization",
				Template:   "Bearer {{ CREDENTIAL }}",
			},
		},
		{
			name: "googleapis",
			want: Template{
				Name:       "googleapis",
				Host:       "*.googleapis.com",
				InjectType: "header",
				HeaderName: "authorization",
				Template:   "Bearer {{ CREDENTIAL }}",
			},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := Lookup(tc.name)
			require.True(t, ok, "expected %q to be a registered template", tc.name)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Lookup(%q) mismatch (-want +got):\n%s", tc.name, diff)
			}
		})
	}
}

func TestLookupUnknownReturnsFalse(t *testing.T) {
	t.Parallel()
	got, ok := Lookup("does-not-exist")
	require.False(t, ok)
	require.Equal(t, Template{}, got)
}

func TestLookupIsCaseInsensitive(t *testing.T) {
	t.Parallel()
	upper, ok := Lookup("ANTHROPIC")
	require.True(t, ok)
	lower, ok := Lookup("anthropic")
	require.True(t, ok)
	require.Equal(t, lower, upper)
}

func TestNamesReturnsSortedRegistry(t *testing.T) {
	t.Parallel()
	names := Names()
	require.NotEmpty(t, names)

	require.ElementsMatch(t, []string{"anthropic", "openai", "github", "stripe", "googleapis"}, names)

	sorted := append([]string(nil), names...)
	sort.Strings(sorted)
	require.Equal(t, sorted, names, "Names must be returned in sorted order")
}
