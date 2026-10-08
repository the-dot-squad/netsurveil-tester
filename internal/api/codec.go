package api

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/the-dot-squad/netsurveil-tester/internal/envelope"
	"github.com/the-dot-squad/netsurveil-tester/internal/jobs"
)

// MaxRIDLen bounds Request.RID.
const MaxRIDLen = 64

// Codec seals and opens the protocol messages for one node. The node side
// uses OpenRequest and SealResponse; controllers use SealRequest and
// OpenResponse. It is safe for concurrent use.
type Codec struct {
	box *envelope.Box
}

// NewCodec derives the node's keys from secret.
func NewCodec(secret []byte, nodeID string) (*Codec, error) {
	box, err := envelope.New(secret, nodeID)
	if err != nil {
		return nil, err
	}
	return &Codec{box: box}, nil
}

// NodeID returns the node the codec is bound to.
func (c *Codec) NodeID() string { return c.box.NodeID() }

// SealRequest seals req, assigning a random RID when it has none, and returns
// the envelope and the RID its response must echo.
func (c *Codec) SealRequest(req Request) (sealed []byte, rid string, err error) {
	return c.SealRequestAt(req, time.Now())
}

// SealRequestAt is SealRequest with an explicit envelope timestamp.
func (c *Codec) SealRequestAt(req Request, at time.Time) (sealed []byte, rid string, err error) {
	if req.RID == "" {
		req.RID = NewRID()
	}
	pt, err := json.Marshal(req)
	if err != nil {
		return nil, "", err
	}
	sealed, err = c.box.SealAt(envelope.Request, pt, at)
	return sealed, req.RID, err
}

// OpenRequest authenticates a sealed request and decodes it strictly. Each
// request opens successfully only once.
func (c *Codec) OpenRequest(raw []byte) (Request, error) {
	var req Request
	pt, err := c.box.Open(envelope.Request, raw)
	if err != nil {
		return req, err
	}
	dec := json.NewDecoder(bytes.NewReader(pt))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		return req, fmt.Errorf("decode request: %w", err)
	}
	if req.RID == "" || len(req.RID) > MaxRIDLen {
		return req, errors.New("request id missing or too long")
	}
	return req, nil
}

// SealResponse seals resp.
func (c *Codec) SealResponse(resp Response) ([]byte, error) {
	pt, err := json.Marshal(resp)
	if err != nil {
		return nil, err
	}
	return c.box.Seal(envelope.Response, pt)
}

// OpenResponse authenticates a sealed response to the request rid and returns
// its job. An application error from the node is returned as an error.
func (c *Codec) OpenResponse(raw []byte, rid string) (*jobs.Job, error) {
	pt, err := c.box.Open(envelope.Response, raw)
	if err != nil {
		return nil, errors.New("response failed authentication")
	}
	var resp Response
	if err := json.Unmarshal(pt, &resp); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if resp.RID != rid || resp.Node != c.NodeID() {
		return nil, errors.New("response does not belong to this request")
	}
	if resp.Error != "" {
		return nil, fmt.Errorf("node: %s", resp.Error)
	}
	if resp.Job == nil {
		return nil, errors.New("node returned no job")
	}
	return resp.Job, nil
}

// NewRID returns a random request id.
func NewRID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
