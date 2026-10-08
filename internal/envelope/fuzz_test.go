package envelope

import (
	"bytes"
	"testing"
)

func FuzzOpen(f *testing.F) {
	box, err := New(bytes.Repeat([]byte{1}, 32), "fuzz-node")
	if err != nil {
		f.Fatal(err)
	}
	valid, err := box.Seal(Request, []byte(`{"rid":"r"}`))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte(`{"v":1,"n":"","ts":0,"ct":""}`))
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		pt, err := box.Open(Request, raw)
		if err != nil && pt != nil {
			t.Fatal("plaintext returned with an error")
		}
	})
}
