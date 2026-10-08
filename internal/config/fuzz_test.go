package config

import "testing"

func FuzzParseSecret(f *testing.F) {
	f.Add("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
	f.Add("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		b, err := ParseSecret(s)
		if err == nil && len(b) != SecretSize {
			t.Fatalf("accepted a %d-byte secret", len(b))
		}
	})
}
