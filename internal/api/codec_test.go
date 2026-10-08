package api_test

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/the-dot-squad/netsurveil-tester/internal/api"
	"github.com/the-dot-squad/netsurveil-tester/internal/check"
	"github.com/the-dot-squad/netsurveil-tester/internal/envelope"
	"github.com/the-dot-squad/netsurveil-tester/internal/jobs"
)

var secret = bytes.Repeat([]byte{3}, 32)

func codec(t *testing.T, node string) *api.Codec {
	t.Helper()
	c, err := api.NewCodec(secret, node)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRoundTrip(t *testing.T) {
	ctl, node := codec(t, "n1"), codec(t, "n1")
	sealed, rid, err := ctl.SealRequest(api.Request{Op: api.OpSubmit, Checks: []check.Spec{{Type: "info"}}})
	if err != nil || rid == "" {
		t.Fatalf("seal: %q %v", rid, err)
	}
	req, err := node.OpenRequest(sealed)
	if err != nil || req.RID != rid || req.Op != api.OpSubmit || len(req.Checks) != 1 {
		t.Fatalf("open request: %+v %v", req, err)
	}
	if _, err := node.OpenRequest(sealed); err == nil {
		t.Fatal("request opened twice")
	}

	resp, err := node.SealResponse(api.Response{RID: rid, Node: "n1", Job: &jobs.Job{ID: "j1", State: jobs.Done}})
	if err != nil {
		t.Fatal(err)
	}
	job, err := ctl.OpenResponse(resp, rid)
	if err != nil || job.ID != "j1" {
		t.Fatalf("open response: %+v %v", job, err)
	}
}

func TestSealRequestKeepsRID(t *testing.T) {
	ctl, node := codec(t, "n1"), codec(t, "n1")
	sealed, rid, err := ctl.SealRequest(api.Request{RID: "mine", Op: api.OpGet, JobID: "x"})
	if err != nil || rid != "mine" {
		t.Fatalf("rid %q %v", rid, err)
	}
	if req, err := node.OpenRequest(sealed); err != nil || req.RID != "mine" {
		t.Fatalf("%+v %v", req, err)
	}
}

func TestOpenRequestRejects(t *testing.T) {
	box, _ := envelope.New(secret, "n1")
	sealRaw := func(pt string) []byte {
		b, _ := box.Seal(envelope.Request, []byte(pt))
		return b
	}
	respDir, _ := box.Seal(envelope.Response, []byte(`{"rid":"r","op":"submit"}`))
	cases := map[string][]byte{
		"unknown field":   sealRaw(`{"rid":"r","op":"submit","extra":1}`),
		"missing rid":     sealRaw(`{"op":"submit"}`),
		"long rid":        sealRaw(`{"rid":"` + strings.Repeat("a", api.MaxRIDLen+1) + `","op":"submit"}`),
		"not json":        sealRaw(`nope`),
		"wrong direction": respDir,
	}
	for name, raw := range cases {
		if _, err := codec(t, "n1").OpenRequest(raw); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestOpenResponseRejects(t *testing.T) {
	node := codec(t, "n1")
	other := codec(t, "n2")
	seal := func(c *api.Codec, r api.Response) []byte {
		b, err := c.SealResponse(r)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	job := &jobs.Job{ID: "j"}
	cases := []struct {
		name string
		raw  []byte
		want string
	}{
		{"wrong rid", seal(node, api.Response{RID: "other", Node: "n1", Job: job}), "does not belong"},
		{"wrong node field", seal(node, api.Response{RID: "r", Node: "n2", Job: job}), "does not belong"},
		{"wrong key", seal(other, api.Response{RID: "r", Node: "n2", Job: job}), "authentication"},
		{"app error", seal(node, api.Response{RID: "r", Node: "n1", Error: "too many active jobs"}), "node: too many active jobs"},
		{"no job", seal(node, api.Response{RID: "r", Node: "n1"}), "no job"},
	}
	for _, c := range cases {
		if _, err := node.OpenResponse(c.raw, "r"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want %q", c.name, err, c.want)
		}
	}
}

func TestSealRequestAtStale(t *testing.T) {
	ctl, node := codec(t, "n1"), codec(t, "n1")
	sealed, _, err := ctl.SealRequestAt(api.Request{Op: api.OpSubmit}, time.Now().Add(-5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := node.OpenRequest(sealed); err == nil {
		t.Fatal("stale request accepted")
	}
	var w struct{ TS int64 }
	_ = json.Unmarshal(sealed, &w)
	if time.Since(time.Unix(w.TS, 0)) < 4*time.Minute {
		t.Fatalf("timestamp not applied: %d", w.TS)
	}
}
