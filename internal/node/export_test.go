package node

import (
	"testing"
	"time"
)

// SetFeedJobWait shortens how long a feed submit may run, for one test.
func SetFeedJobWait(t *testing.T, d time.Duration) {
	old := feedJobWait
	feedJobWait = d
	t.Cleanup(func() { feedJobWait = old })
}
