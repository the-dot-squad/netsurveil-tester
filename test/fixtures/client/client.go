// Package client is the controller side of the direct transport: it seals
// requests, sends them to a reachable node, and verifies responses. Pull-mode
// nodes read their requests from an S3 feed written by the website instead.
package client

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/the-dot-squad/netsurveil-tester/internal/api"
	"github.com/the-dot-squad/netsurveil-tester/internal/check"
	"github.com/the-dot-squad/netsurveil-tester/internal/jobs"
)

const maxResponse = 8 << 20

// Config selects the node and how to reach it.
type Config struct {
	NodeID     string
	Secret     []byte
	NodeURL    string // e.g. https://node1.example.org:8443/prefix
	HTTPClient *http.Client
	// PollInterval is how often Run polls for completion (default 1s).
	PollInterval time.Duration
}

// Client is safe for concurrent use.
type Client struct {
	codec *api.Codec
	base  string
	hc    *http.Client
	poll  time.Duration
}

// New validates cfg and returns a client.
func New(cfg Config) (*Client, error) {
	if cfg.NodeURL == "" {
		return nil, errors.New("node URL is required")
	}
	codec, err := api.NewCodec(cfg.Secret, cfg.NodeID)
	if err != nil {
		return nil, err
	}
	c := &Client{codec: codec, base: strings.TrimRight(cfg.NodeURL, "/"), hc: cfg.HTTPClient, poll: cfg.PollInterval}
	if c.hc == nil {
		c.hc = &http.Client{Timeout: 90 * time.Second}
	}
	if c.poll <= 0 {
		c.poll = time.Second
	}
	return c, nil
}

// Run submits checks and returns the finished job, polling as needed.
func (c *Client) Run(ctx context.Context, checks []check.Spec) (*jobs.Job, error) {
	job, err := c.Submit(ctx, checks, true)
	if err != nil {
		return nil, err
	}
	// On failure the last known state is returned, so the caller can still cancel the job.
	for job.State == jobs.Running {
		if err := sleep(ctx, c.poll); err != nil {
			return job, err
		}
		next, err := c.Status(ctx, job.ID)
		if err != nil {
			return job, err
		}
		job = next
	}
	return job, nil
}

// Submit starts a job. With wait, the node holds the request until the job
// finishes or about a minute passes.
func (c *Client) Submit(ctx context.Context, checks []check.Spec, wait bool) (*jobs.Job, error) {
	return c.direct(ctx, http.MethodPost, "/v1/jobs", api.Request{Op: api.OpSubmit, Checks: checks, Wait: wait})
}

// Status fetches a job.
func (c *Client) Status(ctx context.Context, jobID string) (*jobs.Job, error) {
	return c.direct(ctx, http.MethodGet, "/v1/jobs/"+url.PathEscape(jobID), api.Request{Op: api.OpGet, JobID: jobID})
}

// Cancel stops a job.
func (c *Client) Cancel(ctx context.Context, jobID string) (*jobs.Job, error) {
	return c.direct(ctx, http.MethodDelete, "/v1/jobs/"+url.PathEscape(jobID), api.Request{Op: api.OpCancel, JobID: jobID})
}

func (c *Client) direct(ctx context.Context, method, path string, req api.Request) (*jobs.Job, error) {
	sealed, rid, err := c.codec.SealRequest(req)
	if err != nil {
		return nil, err
	}
	var body io.Reader
	if method == http.MethodPost {
		body = bytes.NewReader(sealed)
	}
	hreq, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, err
	}
	if method != http.MethodPost {
		hreq.Header.Set("Authorization", "NST "+base64.StdEncoding.EncodeToString(sealed))
	}
	hreq.Header.Set("Content-Type", "application/json")
	raw, status, err := c.do(hreq)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("node rejected the request (HTTP %d): check node id, secret, URL and clock", status)
	}
	return c.codec.OpenResponse(raw, rid)
}

func (c *Client) do(r *http.Request) ([]byte, int, error) {
	resp, err := c.hc.Do(r)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	return raw, resp.StatusCode, err
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
