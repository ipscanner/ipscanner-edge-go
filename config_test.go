package edge

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	g, err := New(Config{APIKey: "k", Logger: func(string) {}})
	if err != nil {
		t.Fatal(err)
	}
	s := g.s
	if s.apiURL != DefaultAPIURL || s.timeout != 1500*time.Millisecond || s.cacheTTL != 10*time.Minute ||
		s.policyTTL != 30*time.Second || s.cacheSize != 10000 || s.mode != "" || len(s.block) != 1 ||
		!s.block[ClassMaliciousAutomation] || s.skip == nil || s.ipHeaders[0] != "X-Forwarded-For" ||
		s.userAgent != "ipscanner-edge-go/"+Version || s.source != "" || s.blockMessage != DefaultBlockMessage {
		t.Fatalf("%+v", s)
	}
	d := DefaultConfig()
	if d.Mode != ModeMonitor || d.SkipPaths != DefaultSkipPaths || d.Timeout != DefaultTimeout {
		t.Fatalf("%+v", d)
	}
}

func TestConfigParsing(t *testing.T) {
	g, err := New(Config{
		APIURL:         "http://localhost:3050///",
		Mode:           " Enforce ",
		BlockClasses:   []string{"tor, VPN", "proxy"},
		TrustedProxies: []string{"10.0.0.0/8, 192.0.2.1", "cloudflare"},
		IPHeaders:      []string{"cf-connecting-ip"},
		Source:         "Caddy",
		Client:         "caddy",
		Version:        "1.2.3",
		Logger:         func(string) {},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := g.s
	if s.apiURL != "http://localhost:3050" || s.mode != ModeEnforce || len(s.block) != 3 || !s.block["vpn"] ||
		s.ipHeaders[0] != "Cf-Connecting-Ip" || s.source != "caddy" || s.userAgent != "ipscanner-caddy/1.2.3" {
		t.Fatalf("%+v", s)
	}
	if !inRanges("192.0.2.1", s.trusted) || !inRanges("104.16.1.1", s.trusted) || inRanges("192.0.2.2", s.trusted) {
		t.Fatal("trusted ranges")
	}
}

func TestConfigErrors(t *testing.T) {
	bad := []Config{
		{APIURL: "ftp://x"},
		{APIURL: "not a url"},
		{SiteID: "site-123"},
		{SiteID: "abc"},
		{Mode: "block"},
		{BlockClasses: []string{"human"}},
		{BlockClasses: []string{"verified_bot"}},
		{BlockClasses: []string{"bots"}},
		{TrustedProxies: []string{"10.0.0.0/33"}},
		{TrustedProxies: []string{"example.com"}},
		{SkipPaths: "("},
		{Source: "bad source"},
		{Client: "a/b"},
	}
	for _, c := range bad {
		c.Logger = func(string) {}
		if _, err := New(c); err == nil {
			t.Fatalf("no error for %+v", c)
		} else if !strings.HasPrefix(err.Error(), "ipscanner: ") {
			t.Fatalf("error %q", err)
		}
	}
}

func TestNoKeyWarnsOnce(t *testing.T) {
	var lines []string
	_, err := New(Config{Logger: func(l string) { lines = append(lines, l) }})
	if err != nil || len(lines) != 1 || !strings.Contains(lines[0], "no API key") {
		t.Fatalf("%v %v", err, lines)
	}
}

func TestClientIP(t *testing.T) {
	trusted, _ := parseRanges([]string{"10.0.0.0/8", "private"})
	headers := []string{"X-Forwarded-For"}
	cases := []struct {
		name, remote string
		xff          []string
		trusted      []ipRange
		want         string
	}{
		{"no trusted proxies", "203.0.113.9:443", []string{"1.1.1.1"}, nil, "203.0.113.9"},
		{"untrusted peer spoofing", "203.0.113.9:443", []string{"185.220.101.1"}, trusted, "203.0.113.9"},
		{"trusted peer", "10.0.0.2:443", []string{"84.128.0.1"}, trusted, "84.128.0.1"},
		{"rightmost untrusted", "10.0.0.2:443", []string{"6.6.6.6, 84.128.0.1, 10.0.0.5"}, trusted, "84.128.0.1"},
		{"spoofed left part ignored", "10.0.0.2:443", []string{"1.2.3.4", "84.128.0.1"}, trusted, "84.128.0.1"},
		{"all trusted", "10.0.0.2:443", []string{"10.0.0.9, 10.0.0.8"}, trusted, "10.0.0.9"},
		{"invalid hop", "10.0.0.2:443", []string{"junk, 10.0.0.8"}, trusted, "10.0.0.8"},
		{"invalid only", "10.0.0.2:443", []string{"junk"}, trusted, "10.0.0.2"},
		{"no header", "10.0.0.2:443", nil, trusted, "10.0.0.2"},
		{"port in hop", "10.0.0.2:443", []string{"84.128.0.1:5555"}, trusted, "84.128.0.1"},
		{"ipv6 hop", "[::1]:443", []string{"[2001:db8::1]:80"}, trusted, "2001:db8::1"},
		{"mapped peer", "[::ffff:10.0.0.2]:443", []string{"84.128.0.1"}, trusted, "84.128.0.1"},
		{"bad remote", "nonsense", []string{"84.128.0.1"}, trusted, ""},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		for _, v := range c.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		if got := clientIP(r, c.trusted, headers); got != c.want {
			t.Fatalf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestClientIPCloudflare(t *testing.T) {
	g, err := New(Config{TrustedProxies: []string{"cloudflare"}, IPHeaders: []string{"CF-Connecting-IP"}, Logger: func(string) {}})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.RemoteAddr = "172.68.1.1:443"
	r.Header.Set("CF-Connecting-IP", "84.128.0.1")
	r.Header.Set("X-Forwarded-For", "6.6.6.6")
	if got := g.ClientIP(r); got != "84.128.0.1" {
		t.Fatal(got)
	}
	r.RemoteAddr = "84.1.1.1:443"
	if got := g.ClientIP(r); got != "84.1.1.1" {
		t.Fatal(got)
	}
}

func TestSignalAndStripHeaders(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Accept-Encoding", "gzip")
	r.Header.Set("Sec-Fetch-Mode", "navigate")
	r.Header.Set("Sec-Ch-Ua", strings.Repeat("x", 600))
	r.Header.Set("Cookie", "c=1")
	r.Header.Set("Authorization", "Bearer x")
	h := SignalHeaders(r.Header)
	if len(h) != 4 || h["accept"] != "text/html" || h["sec-fetch-mode"] != "navigate" || len(h["sec-ch-ua"]) != 512 {
		t.Fatalf("%v", h)
	}
	r.Header.Set("X-IPScanner-Class", "human")
	r.Header.Set("x-ipscanner-action", "allow")
	r.Header["x-ipscanner-raw"] = []string{"1"}
	StripHeaders(r.Header)
	for k := range r.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-ipscanner-") {
			t.Fatalf("kept %s", k)
		}
	}
}

func TestIsPublic(t *testing.T) {
	for ip, want := range map[string]bool{
		"84.128.0.1": true, "2001:4860::1": true, "10.1.1.1": false, "172.16.0.1": false,
		"127.0.0.1": false, "::1": false, "fe80::1": false, "0.0.0.0": false, "junk": false,
	} {
		if isPublic(ip) != want {
			t.Fatalf("%s", ip)
		}
	}
}

func TestCheckNormalizesIP(t *testing.T) {
	g, _ := New(Config{Logger: func(string) {}})
	if d := g.CheckVisitor(context.Background(), Visitor{IP: "::ffff:10.0.0.1", Method: "GET", Path: "/"}); d.IP != "10.0.0.1" || d.Status != StatusSkipped {
		t.Fatalf("%+v", d)
	}
}
