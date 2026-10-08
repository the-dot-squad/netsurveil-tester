package envelope

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

var update = flag.Bool("update", false, "rewrite docs/testvectors.json")

const vectorsPath = "../../docs/testvectors.json"

func testSecret() []byte {
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

func newBox(t *testing.T, node string, now time.Time) *Box {
	t.Helper()
	b, err := New(testSecret(), node)
	if err != nil {
		t.Fatal(err)
	}
	b.now = func() time.Time { return now }
	return b
}

func TestRoundTripBothDirections(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ctl, node := newBox(t, "n1", now), newBox(t, "n1", now)
	for _, dir := range []Direction{Request, Response} {
		raw, err := ctl.Seal(dir, []byte(`{"op":"submit"}`))
		if err != nil {
			t.Fatal(err)
		}
		pt, err := node.Open(dir, raw)
		if err != nil || string(pt) != `{"op":"submit"}` {
			t.Fatalf("%s: got %q, %v", dir, pt, err)
		}
	}
}

func TestOpenRejects(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ctl := newBox(t, "n1", now)
	good, _ := ctl.Seal(Request, []byte("hello"))

	other, _ := New(bytes.Repeat([]byte{9}, 32), "n1")
	wrongKey, _ := other.Seal(Request, []byte("hello"))

	otherNode := newBox(t, "n2", now)
	wrongNode, _ := otherNode.Seal(Request, []byte("hello"))

	expired, _ := ctl.SealAt(Request, []byte("hello"), now.Add(-3*time.Minute))
	future, _ := ctl.SealAt(Request, []byte("hello"), now.Add(3*time.Minute))
	oldResp, _ := ctl.SealAt(Response, []byte("hello"), now.Add(-2*time.Hour))

	var w wire
	_ = json.Unmarshal(good, &w)
	ct, _ := base64.StdEncoding.DecodeString(w.CT)
	ct[0] ^= 1
	w.CT = base64.StdEncoding.EncodeToString(ct)
	tampered, _ := json.Marshal(w)

	_ = json.Unmarshal(good, &w)
	w.TS++
	shiftedTS, _ := json.Marshal(w)

	cases := []struct {
		name string
		dir  Direction
		raw  []byte
	}{
		{"wrong key", Request, wrongKey},
		{"wrong node", Request, wrongNode},
		{"expired", Request, expired},
		{"future", Request, future},
		{"old response", Response, oldResp},
		{"tampered ct", Request, tampered},
		{"tampered ts", Request, shiftedTS},
		{"wrong direction", Response, good},
		{"garbage", Request, []byte("{not json")},
		{"empty", Request, nil},
	}
	for _, c := range cases {
		node := newBox(t, "n1", now)
		if _, err := node.Open(c.dir, c.raw); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", c.name, err)
		}
	}
}

func TestReplayRejected(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ctl, node := newBox(t, "n1", now), newBox(t, "n1", now)
	raw, _ := ctl.Seal(Request, []byte("x"))
	if _, err := node.Open(Request, raw); err != nil {
		t.Fatal(err)
	}
	if _, err := node.Open(Request, raw); !errors.Is(err, ErrInvalid) {
		t.Fatalf("replay accepted: %v", err)
	}
	resp, _ := ctl.Seal(Response, []byte("y"))
	for range 2 {
		if _, err := node.Open(Response, resp); err != nil {
			t.Fatalf("responses are not single-use: %v", err)
		}
	}
}

func TestReplayConcurrent(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	ctl, node := newBox(t, "n1", now), newBox(t, "n1", now)
	raw, _ := ctl.Seal(Request, []byte("x"))
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for range 32 {
		wg.Go(func() {
			if _, err := node.Open(Request, raw); err == nil {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		})
	}
	wg.Wait()
	if ok != 1 {
		t.Fatalf("opened %d times, want 1", ok)
	}
}

type vector struct {
	Name      string    `json:"name"`
	SecretHex string    `json:"secret_hex"`
	NodeID    string    `json:"node_id"`
	Direction Direction `json:"direction"`
	TS        int64     `json:"ts"`
	NonceB64  string    `json:"nonce_b64"`
	Plaintext string    `json:"plaintext"`
	AAD       string    `json:"aad"`
	Envelope  string    `json:"envelope"`
	KeyHex    string    `json:"derived_key_hex"`
}

func buildVectors(t *testing.T) []vector {
	t.Helper()
	nonce := make([]byte, 24)
	for i := range nonce {
		nonce[i] = byte(0xa0 + i)
	}
	inputs := []struct {
		name string
		dir  Direction
		pt   string
	}{
		{"request-submit", Request, `{"rid":"r1","op":"submit","checks":[{"type":"web","target":"https://x.com"}],"reply":["https://s3.eu-west-1.amazonaws.com/netsurveil/results/node-1/r1.json?X-Amz-Signature=00"]}`},
		{"response-error", Response, `{"rid":"r1","node":"node-1","version":"dev","error":"unknown job"}`},
	}
	b, _ := New(testSecret(), "node-1")
	var out []vector
	for _, in := range inputs {
		const ts = 1_800_000_000
		raw, err := b.seal(in.dir, []byte(in.pt), ts, nonce)
		if err != nil {
			t.Fatal(err)
		}
		key, err := hkdf.Key(sha256.New, testSecret(), nil, "nst/v1/"+string(in.dir), 32)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, vector{
			Name:      in.name,
			SecretHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			NodeID:    "node-1",
			Direction: in.dir,
			TS:        ts,
			NonceB64:  base64.StdEncoding.EncodeToString(nonce),
			Plaintext: in.pt,
			AAD:       string(aad("node-1", in.dir, ts)),
			Envelope:  string(raw),
			KeyHex:    hex.EncodeToString(key),
		})
	}
	return out
}

func TestVectors(t *testing.T) {
	want := buildVectors(t)
	if *update {
		data, _ := json.MarshalIndent(want, "", "  ")
		if err := os.WriteFile(vectorsPath, append(data, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors (run `make vectors`): %v", err)
	}
	var got []vector
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) {
		t.Fatalf("vector count %d, want %d", len(got), len(want))
	}
	for i, v := range got {
		if v.Envelope != want[i].Envelope || v.KeyHex != want[i].KeyHex {
			t.Errorf("%s: published vector no longer matches implementation", v.Name)
		}
		box := newBox(t, v.NodeID, time.Unix(v.TS, 0))
		pt, err := box.Open(v.Direction, []byte(v.Envelope))
		if err != nil || string(pt) != v.Plaintext || !strings.Contains(v.AAD, v.NodeID) {
			t.Errorf("%s: open failed: %v", v.Name, err)
		}
	}
}
