package api_test

import (
	"bytes"
	"testing"

	"github.com/the-dot-squad/netsurveil-tester/internal/api"
	"github.com/the-dot-squad/netsurveil-tester/internal/check"
)

func FuzzOpenRequest(f *testing.F) {
	codec, err := api.NewCodec(bytes.Repeat([]byte{2}, 32), "fuzz-node")
	if err != nil {
		f.Fatal(err)
	}
	valid, _, err := codec.SealRequest(api.Request{Op: api.OpSubmit, Checks: []check.Spec{{Type: "info"}}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{"v":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		req, err := codec.OpenRequest(raw)
		if err == nil && (req.RID == "" || len(req.RID) > api.MaxRIDLen) {
			t.Fatalf("accepted request with rid %q", req.RID)
		}
	})
}
