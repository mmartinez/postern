package config_test

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/mmartinez/postern/internal/config"
)

// TestProxyCacheSettings covers the resolution of effective cache settings from
// the optional cache block and the legacy cache_ttl scalar, including defaults
// and the refresh_ahead derivation (75% of ttl).
func TestProxyCacheSettings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		proxy config.Proxy
		want  config.CacheSettings
	}{
		{
			name:  "defaults when nothing set",
			proxy: config.Proxy{},
			want:  config.CacheSettings{TTL: time.Hour, RefreshAhead: 45 * time.Minute, MaxStale: 24 * time.Hour},
		},
		{
			name:  "legacy cache_ttl maps to ttl and derives refresh_ahead",
			proxy: config.Proxy{CacheTTL: 5 * time.Minute},
			want:  config.CacheSettings{TTL: 5 * time.Minute, RefreshAhead: 225 * time.Second, MaxStale: 24 * time.Hour},
		},
		{
			name:  "full cache block wins",
			proxy: config.Proxy{Cache: &config.Cache{TTL: 2 * time.Hour, RefreshAhead: time.Hour, MaxStale: 48 * time.Hour}},
			want:  config.CacheSettings{TTL: 2 * time.Hour, RefreshAhead: time.Hour, MaxStale: 48 * time.Hour},
		},
		{
			name:  "cache block ttl only derives refresh_ahead, defaults max_stale",
			proxy: config.Proxy{Cache: &config.Cache{TTL: 30 * time.Minute}},
			want:  config.CacheSettings{TTL: 30 * time.Minute, RefreshAhead: 1350 * time.Second, MaxStale: 24 * time.Hour},
		},
		{
			name:  "cache_ttl supplies ttl while block supplies refresh_ahead",
			proxy: config.Proxy{CacheTTL: 10 * time.Minute, Cache: &config.Cache{RefreshAhead: 5 * time.Minute}},
			want:  config.CacheSettings{TTL: 10 * time.Minute, RefreshAhead: 5 * time.Minute, MaxStale: 24 * time.Hour},
		},
		{
			name:  "max_stale default clamps up to ttl when ttl exceeds the default",
			proxy: config.Proxy{Cache: &config.Cache{TTL: 48 * time.Hour}},
			want:  config.CacheSettings{TTL: 48 * time.Hour, RefreshAhead: 36 * time.Hour, MaxStale: 48 * time.Hour},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := tc.proxy.CacheSettings()
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Fatalf("CacheSettings() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
