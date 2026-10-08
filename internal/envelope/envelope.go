// Package envelope seals and opens authenticated, encrypted messages exchanged
// between a controller and a node that share a 32-byte secret.
//
// Wire format (JSON): {"v":1,"node":"<id>","ts":<unix>,"nonce":"<b64 24B>","ct":"<b64>"}
// Cipher: XChaCha20-Poly1305 with per-direction keys derived by HKDF-SHA256.
// Additional data: "nst/v1|<node>|<dir>|<ts>".
//
// Requests must be within ±120s of the receiver's clock and are single-use
// (nonce replay cache). Responses must be at most one hour old; they are bound
// to their request by the caller (request id echo), not by this package.
package envelope

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

// Version is the wire format revision carried in the "v" field.
const Version = 1

// Direction selects the key and freshness policy for a message.
type Direction string

const (
	Request  Direction = "req"
	Response Direction = "resp"
)

// ErrInvalid is the only error Open returns, so failures reveal nothing to a prober.
var ErrInvalid = errors.New("envelope: invalid")

const (
	requestWindow  = 120 * time.Second
	responseMaxAge = time.Hour
	maxNonces      = 100_000
)

type wire struct {
	V     int    `json:"v"`
	Node  string `json:"node"`
	TS    int64  `json:"ts"`
	Nonce string `json:"nonce"`
	CT    string `json:"ct"`
}

// Box holds the derived keys for one node and the request replay cache.
// It is safe for concurrent use.
type Box struct {
	nodeID string
	aeads  map[Direction]cipher.AEAD
	now    func() time.Time

	mu   sync.Mutex
	seen map[string]int64 // request nonce -> unix expiry
}

// New derives keys from secret for nodeID.
func New(secret []byte, nodeID string) (*Box, error) {
	if len(secret) != 32 {
		return nil, errors.New("envelope: secret must be 32 bytes")
	}
	if nodeID == "" {
		return nil, errors.New("envelope: node id required")
	}
	b := &Box{nodeID: nodeID, aeads: map[Direction]cipher.AEAD{}, now: time.Now, seen: map[string]int64{}}
	for _, d := range []Direction{Request, Response} {
		key, err := hkdf.Key(sha256.New, secret, nil, "nst/v1/"+string(d), chacha20poly1305.KeySize)
		if err != nil {
			return nil, err
		}
		aead, err := chacha20poly1305.NewX(key)
		if err != nil {
			return nil, err
		}
		b.aeads[d] = aead
	}
	return b, nil
}

// NodeID returns the node identifier the box is bound to.
func (b *Box) NodeID() string { return b.nodeID }

// Seal encrypts plaintext for the given direction, timestamped now.
func (b *Box) Seal(dir Direction, plaintext []byte) ([]byte, error) {
	return b.SealAt(dir, plaintext, b.now())
}

// SealAt encrypts plaintext with an explicit timestamp.
func (b *Box) SealAt(dir Direction, plaintext []byte, at time.Time) ([]byte, error) {
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return b.seal(dir, plaintext, at.Unix(), nonce)
}

func (b *Box) seal(dir Direction, plaintext []byte, ts int64, nonce []byte) ([]byte, error) {
	aead, ok := b.aeads[dir]
	if !ok {
		return nil, fmt.Errorf("envelope: unknown direction %q", dir)
	}
	ct := aead.Seal(nil, nonce, plaintext, aad(b.nodeID, dir, ts))
	return json.Marshal(wire{
		V:     Version,
		Node:  b.nodeID,
		TS:    ts,
		Nonce: base64.StdEncoding.EncodeToString(nonce),
		CT:    base64.StdEncoding.EncodeToString(ct),
	})
}

// Open authenticates and decrypts raw. Requests are additionally checked for
// freshness and replay; a request can be opened successfully only once.
func (b *Box) Open(dir Direction, raw []byte) ([]byte, error) {
	aead, ok := b.aeads[dir]
	if !ok {
		return nil, ErrInvalid
	}
	var w wire
	if err := json.Unmarshal(raw, &w); err != nil || w.V != Version || w.Node != b.nodeID {
		return nil, ErrInvalid
	}
	nonce, err := base64.StdEncoding.DecodeString(w.Nonce)
	if err != nil || len(nonce) != chacha20poly1305.NonceSizeX {
		return nil, ErrInvalid
	}
	ct, err := base64.StdEncoding.DecodeString(w.CT)
	if err != nil {
		return nil, ErrInvalid
	}

	now := b.now()
	msgTime := time.Unix(w.TS, 0)
	switch dir {
	case Request:
		if msgTime.Before(now.Add(-requestWindow)) || msgTime.After(now.Add(requestWindow)) {
			return nil, ErrInvalid
		}
	case Response:
		if msgTime.Before(now.Add(-responseMaxAge)) || msgTime.After(now.Add(requestWindow)) {
			return nil, ErrInvalid
		}
	}

	plaintext, err := aead.Open(nil, nonce, ct, aad(b.nodeID, dir, w.TS))
	if err != nil {
		return nil, ErrInvalid
	}
	if dir == Request && !b.remember(w.Nonce, w.TS+int64(requestWindow/time.Second), now.Unix()) {
		return nil, ErrInvalid
	}
	return plaintext, nil
}

// remember records a request nonce and reports whether it was unseen.
// Only authenticated nonces reach here, so the cache cannot be flooded by forgeries.
func (b *Box) remember(nonce string, expiry, now int64) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, dup := b.seen[nonce]; dup {
		return false
	}
	if len(b.seen) >= maxNonces {
		for n, exp := range b.seen {
			if exp < now {
				delete(b.seen, n)
			}
		}
		if len(b.seen) >= maxNonces {
			return false
		}
	}
	b.seen[nonce] = expiry
	return true
}

func aad(node string, dir Direction, ts int64) []byte {
	return fmt.Appendf(nil, "nst/v%d|%s|%s|%d", Version, node, dir, ts)
}
