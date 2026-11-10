package proxy

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestFailureThrottleBoundsAndLoopbackNormalization(t *testing.T) {
	t.Parallel()
	now := time.Unix(1, 0)
	f := newFailureThrottle(func() time.Time { return now })
	for range 5 {
		d, release, ok := f.failure("127.0.0.1:1")
		require.True(t, ok)
		require.Zero(t, d)
		release()
	}
	var releases []func()
	for i, peer := range []string{"[::1]:1", "127.0.0.2:2", "[::ffff:127.0.0.1]:3", "127.0.0.1:4"} {
		d, release, ok := f.failure(peer)
		require.True(t, ok)
		require.Equal(t, 100*time.Millisecond*time.Duration(1<<i), d)
		releases = append(releases, release)
	}
	_, _, ok := f.failure("127.0.0.1:5")
	require.False(t, ok)
	for _, release := range releases {
		release()
		release()
	}
	now = now.Add(time.Second)
	d, release, ok := f.failure("127.0.0.1:6")
	defer release()
	require.True(t, ok)
	require.Zero(t, d)
}

func TestFailureThrottleGlobalCapacityAndFallback(t *testing.T) {
	t.Parallel()
	now := time.Unix(1, 0)
	f := newFailureThrottle(func() time.Time { return now })
	var releases []func()
	for source := range 64 {
		peer := fmt.Sprintf("10.0.0.%d:1", source+1)
		for range 9 {
			_, release, ok := f.failure(peer)
			require.True(t, ok)
			releases = append(releases, release)
		}
	}
	for range 5 {
		_, release, ok := f.failure("10.1.0.1:1")
		require.True(t, ok)
		release()
	}
	_, _, ok := f.failure("10.1.0.1:1")
	require.False(t, ok, "global delayed-failure capacity was exceeded")
	for _, release := range releases {
		release()
	}
	for range 5 {
		_, release, ok := f.failure("invalid peer")
		require.True(t, ok)
		release()
	}
	delay, release, ok := f.failure("another invalid peer")
	defer release()
	require.True(t, ok)
	require.Positive(t, delay, "overflow sources reset the shared fallback budget")
	for source := range 4096 {
		peer := fmt.Sprintf("10.2.%d.%d:1", source/256, source%256)
		_, release, _ := f.failure(peer)
		release()
	}
	require.LessOrEqual(t, len(f.sources), 4096)
	now = now.Add(11 * time.Minute)
	_, release, ok = f.failure("10.3.0.1:1")
	defer release()
	require.True(t, ok)
	require.Less(t, len(f.sources), 4096, "expired sources were not reclaimed")
}
