// Package api defines the plaintext messages carried inside sealed envelopes.
// See docs/PROTOCOL.md.
package api

import (
	"github.com/the-dot-squad/netsurveil-tester/internal/check"
	"github.com/the-dot-squad/netsurveil-tester/internal/jobs"
)

// MaxReplyURLs bounds Request.Reply.
const MaxReplyURLs = 4

// Op selects what a request asks the node to do.
type Op string

const (
	OpSubmit Op = "submit"
	OpGet    Op = "get"
	OpCancel Op = "cancel"
)

// Request is the plaintext of a request envelope. RID is chosen by the
// controller and echoed in the response to bind the two together.
type Request struct {
	RID    string       `json:"rid"`
	Op     Op           `json:"op"`
	JobID  string       `json:"job_id,omitempty"`
	Checks []check.Spec `json:"checks,omitempty"`
	Wait   bool         `json:"wait,omitempty"`
	// Reply lists presigned PUT URLs, tried in order, where a request read from
	// the feed gets its sealed responses. Direct requests ignore it.
	Reply []string `json:"reply,omitempty"`
}

// Response is the plaintext of a response envelope.
type Response struct {
	RID     string    `json:"rid"`
	Node    string    `json:"node"`
	Version string    `json:"version"`
	Job     *jobs.Job `json:"job,omitempty"`
	Error   string    `json:"error,omitempty"`
}
