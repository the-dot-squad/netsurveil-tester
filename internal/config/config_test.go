package config

import "testing"

const testSecretHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadNodeDefaults(t *testing.T) {
	cfg, err := LoadNode(env(map[string]string{"NODE_ID": "node-1", "NODE_SECRET": testSecretHex}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenAddr != ":8080" || cfg.HealthAddr != DefaultHealthAddr || cfg.LogLevel != "info" ||
		cfg.AllowPrivate || cfg.RateLimitPerMin != 30 || len(cfg.Secret) != 32 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
}

func TestLoadNodeOptionalAddrs(t *testing.T) {
	cfg, err := LoadNode(env(map[string]string{
		"NODE_ID": "n", "NODE_SECRET": testSecretHex, "HEALTH_ADDR": "off", "LOG_LEVEL": "WARN",
		"FEED_URLS": "https://a/f.txt", "LISTEN_ADDR": "off",
	}))
	if err != nil || cfg.HealthAddr != "" || cfg.ListenAddr != "" || cfg.LogLevel != "warn" {
		t.Fatalf("%+v %v", cfg, err)
	}
	cfg, err = LoadNode(env(map[string]string{"NODE_ID": "n", "NODE_SECRET": testSecretHex, "HEALTH_ADDR": "[::1]:9000"}))
	if err != nil || cfg.HealthAddr != "[::1]:9000" {
		t.Fatalf("%+v %v", cfg, err)
	}
}

func TestLoadNodeRejects(t *testing.T) {
	cases := map[string]map[string]string{
		"bad id":        {"NODE_ID": "bad id", "NODE_SECRET": testSecretHex},
		"short secret":  {"NODE_ID": "n", "NODE_SECRET": "abcd"},
		"no mode":       {"NODE_ID": "n", "NODE_SECRET": testSecretHex, "LISTEN_ADDR": "off"},
		"bad feed":      {"NODE_ID": "n", "NODE_SECRET": testSecretHex, "FEED_URLS": "ftp://x/feed.txt"},
		"feed no path":  {"NODE_ID": "n", "NODE_SECRET": testSecretHex, "FEED_URLS": "https://s3.example"},
		"feed dup":      {"NODE_ID": "n", "NODE_SECRET": testSecretHex, "FEED_URLS": "https://a/f.txt,https://a/f.txt"},
		"feed too many": {"NODE_ID": "n", "NODE_SECRET": testSecretHex, "FEED_URLS": "https://a/1,https://a/2,https://a/3,https://a/4,https://a/5,https://a/6,https://a/7,https://a/8,https://a/9"},
		"bad prefix":    {"NODE_ID": "n", "NODE_SECRET": testSecretHex, "HTTP_PATH_PREFIX": "/a/"},
		"bad bool":      {"NODE_ID": "n", "NODE_SECRET": testSecretHex, "ALLOW_PRIVATE_TARGETS": "maybe"},
		"bad ratelimit": {"NODE_ID": "n", "NODE_SECRET": testSecretHex, "RATE_LIMIT_PER_MIN": "-1"},
		"bad log level": {"NODE_ID": "n", "NODE_SECRET": testSecretHex, "LOG_LEVEL": "verbose"},
		"public health": {"NODE_ID": "n", "NODE_SECRET": testSecretHex, "HEALTH_ADDR": "0.0.0.0:8099"},
		"named health":  {"NODE_ID": "n", "NODE_SECRET": testSecretHex, "HEALTH_ADDR": "localhost:8099"},
		"no secret":     {"NODE_ID": "n"},
	}
	for name, m := range cases {
		if _, err := LoadNode(env(m)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestLoadNodeFeedURLs(t *testing.T) {
	cfg, err := LoadNode(env(map[string]string{
		"NODE_ID":     "n",
		"NODE_SECRET": testSecretHex,
		"LISTEN_ADDR": "off",
		"FEED_URLS":   " https://s3.eu-west-1.amazonaws.com/b/feeds/k.txt, ,https://s3-eu-west-1.amazonaws.com/b/feeds/k.txt ",
	}))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://s3.eu-west-1.amazonaws.com/b/feeds/k.txt", "https://s3-eu-west-1.amazonaws.com/b/feeds/k.txt"}
	if len(cfg.FeedURLs) != len(want) || cfg.FeedURLs[0] != want[0] || cfg.FeedURLs[1] != want[1] {
		t.Fatalf("FeedURLs = %q, want %q", cfg.FeedURLs, want)
	}
}

func TestParseSecretFormats(t *testing.T) {
	for _, s := range []string{testSecretHex, "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"} {
		b, err := ParseSecret(s)
		if err != nil || b[31] != 0x1f {
			t.Errorf("ParseSecret(%q) = %x, %v", s, b, err)
		}
	}
}
