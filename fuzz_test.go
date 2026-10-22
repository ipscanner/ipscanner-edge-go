package edge

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

var fuzzTrusted = [][]string{
	nil,
	{"private"},
	{"cloudflare"},
	{"10.0.0.0/8", "2001:db8::/32", "192.0.2.7"},
	{"0.0.0.0/0", "::/0"},
}

func fuzzRequest(remote string, headers map[string][]string) *http.Request {
	r := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/"}, RemoteAddr: remote, Header: http.Header{}}
	for k, v := range headers {
		r.Header[k] = v
	}
	return r.WithContext(context.Background())
}

func validHeaderValue(v string) bool {
	for i := 0; i < len(v); i++ {
		if c := v[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return false
		}
	}
	return true
}

func FuzzNormalizeIP(f *testing.F) {
	for _, s := range []string{
		"84.128.0.1", " 84.128.0.1 ", "84.128.0.1:5555", "[2001:db8::1]:80", "2001:DB8::1",
		"::ffff:10.0.0.1", "[::ffff:10.0.0.1]", "fe80::1%eth0", "[fe80::1%25eth0]:443", "[::1",
		"1.2.3", "1.2.3.4.5", "::", "0.0.0.0", "unknown", "", "999.1.1.1", "01.02.03.04",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := normalizeIP(s)
		if out == "" {
			return
		}
		ip := net.ParseIP(out)
		if ip == nil {
			t.Fatalf("normalizeIP(%q) = %q, not an IP", s, out)
		}
		if again := normalizeIP(out); again != out {
			t.Fatalf("normalizeIP not idempotent: %q -> %q -> %q", s, out, again)
		}
		if ip.To4() != nil && strings.Contains(out, ":") {
			t.Fatalf("normalizeIP(%q) = %q kept an IPv4-mapped form", s, out)
		}
		if p := net.ParseIP(strings.TrimSpace(s)); p != nil && !p.Equal(ip) {
			t.Fatalf("normalizeIP(%q) = %q changed the address", s, out)
		}
	})
}

func FuzzParseRanges(f *testing.F) {
	for _, s := range []string{
		"private", "Cloudflare", "10.0.0.0/8", "192.0.2.7", "2001:db8::/32", "::ffff:10.0.0.0/104",
		"[::1]:80", "fe80::1%eth0", "10.0.0.0/33", "junk", "10.0.0.1,10.0.0.2", "", "1.2.3.4/0",
	} {
		f.Add(s, "10.1.2.3")
	}
	f.Fuzz(func(t *testing.T, entry, ip string) {
		ranges, err := parseRanges(splitList([]string{entry}))
		if err != nil {
			return
		}
		for _, r := range ranges {
			if r.net == nil {
				t.Fatalf("%q produced a nil range", entry)
			}
		}
		if inRanges(ip, ranges) && net.ParseIP(ip) == nil {
			t.Fatalf("%q matched %q although it is not an IP", entry, ip)
		}
		// A trusted single address must match itself.
		if !strings.Contains(entry, "/") && !strings.Contains(entry, ",") {
			if self := normalizeIP(entry); self != "" && !inRanges(self, ranges) {
				t.Fatalf("trusted address %q does not match itself", entry)
			}
		}
	})
}

func FuzzClientIP(f *testing.F) {
	f.Add(uint8(1), "203.0.113.9:443", "185.220.101.1", "", "")
	f.Add(uint8(1), "10.0.0.2:443", "6.6.6.6, 84.128.0.1, 10.0.0.5", "", "")
	f.Add(uint8(1), "10.0.0.2:443", "1.2.3.4", "84.128.0.1", "")
	f.Add(uint8(1), "10.0.0.2:443", "junk, 10.0.0.8", "", "84.128.0.1")
	f.Add(uint8(1), "[::ffff:10.0.0.2]:443", "[2001:db8::1]:80", "", "")
	f.Add(uint8(2), "172.68.1.1:443", "6.6.6.6", "", "84.128.0.1")
	f.Add(uint8(3), "[2001:db8::5]:443", "fe80::1%eth0, 2001:db8::9", "", "")
	f.Add(uint8(4), "84.1.1.1:443", ",,,", "", "")
	f.Add(uint8(0), "nonsense", "84.128.0.1", "", "")
	f.Fuzz(func(t *testing.T, preset uint8, remote, xff1, xff2, realIP string) {
		trusted := fuzzTrusted[int(preset)%len(fuzzTrusted)]
		headers := []string{"X-Forwarded-For", "X-Real-Ip"}
		g, err := New(Config{TrustedProxies: trusted, IPHeaders: headers, Logger: func(string) {}})
		if err != nil {
			t.Fatal(err)
		}
		h := map[string][]string{}
		if xff1 != "" || xff2 != "" {
			h["X-Forwarded-For"] = []string{xff1, xff2}
		}
		if realIP != "" {
			h["X-Real-Ip"] = []string{realIP}
		}
		r := fuzzRequest(remote, h)
		got := g.ClientIP(r)
		peer := remoteIP(r)

		if got != "" && normalizeIP(got) != got {
			t.Fatalf("ClientIP = %q is not a normalized IP", got)
		}
		if !g.TrustedPeer(r) {
			if got != peer {
				t.Fatalf("untrusted peer %q: ClientIP = %q, headers must be ignored", remote, got)
			}
			return
		}
		if got == peer {
			return
		}
		// Every hop right of the chosen address must be a valid, trusted proxy.
		var chain []string
		for _, name := range headers {
			if values := r.Header.Values(name); len(values) > 0 {
				for _, v := range values {
					chain = append(chain, strings.Split(v, ",")...)
				}
				break
			}
		}
		vouched := false
		for i := len(chain) - 1; i >= 0; i-- {
			hop := normalizeIP(chain[i])
			if hop == got {
				vouched = true
				break
			}
			if hop == "" || !inRanges(hop, g.s.trusted) {
				break
			}
		}
		if !vouched {
			t.Fatalf("ClientIP = %q from chain %q is not vouched for by trusted proxies", got, chain)
		}
	})
}

func FuzzValidateConfig(f *testing.F) {
	f.Add("https://ipscanner.io", "site_abc123", "enforce", "tor, vpn", "private,10.0.0.0/8", "X-Forwarded-For", "", "traefik", "traefik", "0.1.2", "Blocked")
	f.Add("http://127.0.0.1:3050/", "", "monitor", "none", "cloudflare", "CF-Connecting-IP", "none", "", "", "", "")
	f.Add("ftp://x", "site_", "block", "human", "junk", "", "(", "bad token", "c", "v", "<b>")
	f.Add("", "site_ABCdef0123456789012345678", "MONITOR", "", "", "x-real-ip, x-forwarded-for", `^/health$`, "caddy", "caddy", "1.0.0+meta", "")
	f.Fuzz(func(t *testing.T, apiURL, site, mode, classes, trusted, ipHeaders, skip, source, client, version, message string) {
		cfg := Config{
			APIURL: apiURL, SiteID: site, Mode: mode, BlockClasses: []string{classes},
			TrustedProxies: []string{trusted}, IPHeaders: []string{ipHeaders}, SkipPaths: skip,
			Source: source, Client: client, Version: version, BlockMessage: message,
		}
		s, err := validate(cfg)
		g, gerr := New(Config{
			APIURL: cfg.APIURL, SiteID: cfg.SiteID, Mode: cfg.Mode, BlockClasses: cfg.BlockClasses,
			TrustedProxies: cfg.TrustedProxies, IPHeaders: cfg.IPHeaders, SkipPaths: cfg.SkipPaths,
			Source: cfg.Source, Client: cfg.Client, Version: cfg.Version, BlockMessage: cfg.BlockMessage,
			Logger: func(string) {},
		})
		if (err == nil) != (gerr == nil) || (gerr == nil) != (g != nil) {
			t.Fatalf("validate err %v, New err %v", err, gerr)
		}
		if err != nil {
			if !strings.HasPrefix(err.Error(), "ipscanner: ") {
				t.Fatalf("error without prefix: %v", err)
			}
			return
		}
		u, perr := url.Parse(s.apiURL)
		if perr != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.HasSuffix(s.apiURL, "/") {
			t.Fatalf("apiURL %q accepted", s.apiURL)
		}
		if s.siteID != "" && !validSiteID(s.siteID) {
			t.Fatalf("siteId %q accepted", s.siteID)
		}
		if s.mode != "" && s.mode != ModeMonitor && s.mode != ModeEnforce {
			t.Fatalf("mode %q accepted", s.mode)
		}
		for c := range s.block {
			if !contains(BlockableClasses, c) || s.local[c] != ActionBlock {
				t.Fatalf("block class %q accepted", c)
			}
		}
		if len(s.ipHeaders) == 0 {
			t.Fatal("no IP headers")
		}
		for _, h := range s.ipHeaders {
			if h == "" || h != http.CanonicalHeaderKey(h) {
				t.Fatalf("IP header %q", h)
			}
		}
		if s.timeout <= 0 || s.cacheTTL <= 0 || s.cacheSize <= 0 || s.policyTTL <= 0 {
			t.Fatalf("non-positive limits: %+v", s)
		}
		if !strings.HasPrefix(s.userAgent, "ipscanner-") || !validHeaderValue(s.userAgent) || strings.ContainsAny(s.userAgent, " \t") {
			t.Fatalf("User-Agent %q", s.userAgent)
		}
		if s.source != "" && !validToken(s.source) {
			t.Fatalf("source %q", s.source)
		}
		if s.blockMessage == "" {
			t.Fatal("empty block message")
		}
	})
}

func FuzzCacheKey(f *testing.F) {
	f.Add("site_a", "84.128.0.1", "ua|x", "site_a|84.128.0.1", "", "x")
	f.Add("", "1.1.1.1", "chrome", "", "1.1.1.1", "chrome ")
	f.Add("site_a", "2001:db8::1", "", "site_a", "2001:db8::1", "")
	f.Fuzz(func(t *testing.T, site1, ip1, ua1, site2, ip2, ua2 string) {
		// Sites are validated and IPs normalized before a key is built.
		for _, s := range []string{site1, site2} {
			if s != "" && !validSiteID(s) {
				return
			}
		}
		for _, ip := range []string{ip1, ip2} {
			if ip == "" || normalizeIP(ip) != ip {
				return
			}
		}
		k1, k2 := cacheKey(site1, ip1, ua1), cacheKey(site2, ip2, ua2)
		if b, err := hex.DecodeString(k1); err != nil || len(b) != 32 {
			t.Fatalf("key %q is not a sha256 hex digest", k1)
		}
		same := site1 == site2 && ip1 == ip2 && ua1 == ua2
		if same != (k1 == k2) {
			t.Fatalf("(%q,%q,%q) and (%q,%q,%q): same tuple %v, same key %v", site1, ip1, ua1, site2, ip2, ua2, same, k1 == k2)
		}
	})
}

func FuzzVerdict(f *testing.F) {
	f.Add([]byte(verdictJSON("human", "human", "residential_clean", false, 3)))
	f.Add([]byte(verdictJSON("tor", "human", "tor", true, 90)))
	f.Add([]byte(`{"class":"verified_bot","agent":{"class":"known_bot","confidence":0.99,"action":"allow","signals":{"allowlist_verified":true}},"network":{"networkClass":"hosting","anonymized":false,"riskScore":5,"country":"US"},"site":null}`))
	f.Add([]byte(`{"class":"human","mode":"monitor","network":{"networkClass":"vpn","riskScore":1e308,"country":"D\nE"},"site":{"id":"site_x","mode":"enforce","policyVersion":7},"degraded":["agent"]}`))
	f.Add([]byte(`{"class":"","agent":{"signals":{"network_origin":5,"anonymized":"yes","allowlist_verified":1}}}`))
	f.Add([]byte(`{"class":"x","network":{"networkClass":"datacenter","riskScore":null,"asn":-1}}`))
	policies := []map[string]string{
		nil,
		{ClassTor: ActionBlock, ClassVPN: ActionFlag, ClassHosting: ActionBlock, ClassHuman: ActionAllow},
		{ClassHuman: ActionBlock, ClassVerifiedBot: ActionBlock, ClassMaliciousAutomation: ActionBlock},
	}
	f.Fuzz(func(t *testing.T, body []byte) {
		var v Verdict
		if json.Unmarshal(body, &v) != nil {
			return
		}
		b1, err := json.Marshal(&v)
		if err != nil {
			t.Fatalf("re-encode: %v", err)
		}
		var v2 Verdict
		if err := json.Unmarshal(b1, &v2); err != nil {
			t.Fatalf("decode own encoding %s: %v", b1, err)
		}
		if b2, _ := json.Marshal(&v2); !bytes.Equal(b1, b2) {
			t.Fatalf("round trip changed the verdict:\n%s\n%s", b1, b2)
		}
		for _, actions := range policies {
			for _, matchNetwork := range []bool{false, true} {
				class, action := decide(&v, actions, matchNetwork)
				if class == "" || (v.Class != "" && class != v.Class) {
					t.Fatalf("class %q for verdict class %q", class, v.Class)
				}
				if action != ActionAllow && action != ActionFlag && action != ActionBlock {
					t.Fatalf("action %q", action)
				}
				if (isVerified(&v) || len(actions) == 0) && action != ActionAllow {
					t.Fatalf("verified or empty policy got %q", action)
				}
				d := Decision{Status: StatusOK, Class: class, Action: action, Outcome: action, Verdict: &v, Site: "site_x"}
				for name, value := range d.Headers() {
					if !strings.HasPrefix(http.CanonicalHeaderKey(name), HeaderPrefix) {
						t.Fatalf("header %q outside the X-IPScanner- namespace", name)
					}
					if !validHeaderValue(value) {
						t.Fatalf("header %s: %q is not a valid header value", name, value)
					}
				}
			}
		}
	})
}

func FuzzPolicy(f *testing.F) {
	f.Add([]byte(policyJSON("enforce", 3, map[string]string{"tor": "block", "vpn": "flag", "human": "allow"})))
	f.Add([]byte(`{"mode":"ENFORCE","policy":{"tor":"BLOCK","nope":"block","vpn":"deny"},"version":-1}`))
	f.Add([]byte(`{"mode":null,"policy":null}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		var b policyBody
		if json.Unmarshal(body, &b) != nil {
			return
		}
		p := toPolicy(b)
		if p.Mode != ModeMonitor && p.Mode != ModeEnforce {
			t.Fatalf("mode %q", p.Mode)
		}
		if p.Mode == ModeEnforce && b.Mode != ModeEnforce {
			t.Fatalf("mode %q became enforce", b.Mode)
		}
		for class, action := range p.Actions {
			if !contains(Classes, class) {
				t.Fatalf("unknown class %q kept", class)
			}
			if action != ActionAllow && action != ActionFlag && action != ActionBlock {
				t.Fatalf("unknown action %q kept", action)
			}
		}
	})
}

func FuzzBlockPage(f *testing.F) {
	f.Add("", "")
	f.Add("2b1c-4f", "Blocked by IPScanner edge guard.")
	f.Add(`"><script>alert(1)</script>`, `</p><img src=x onerror=alert(1)>`)
	f.Add("a&b", "&lt;already escaped&gt;")
	f.Fuzz(func(t *testing.T, id, message string) {
		page := string(BlockPage(id, message))
		tmplID := ""
		if id != "" {
			tmplID = "x"
		}
		tmpl := string(BlockPage(tmplID, "x"))
		for _, c := range []string{"<", ">", `"`} {
			if strings.Count(page, c) != strings.Count(tmpl, c) {
				t.Fatalf("input changed the markup: %q", page)
			}
		}
		text := html.UnescapeString(page)
		if message != "" && !strings.Contains(text, message) {
			t.Fatalf("message %q missing", message)
		}
		if id != "" && !strings.Contains(text, id) {
			t.Fatalf("request ID %q missing", id)
		}
	})
}

type fuzzTransport struct {
	body []byte
}

func (f *fuzzTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
	body := f.body
	if strings.HasSuffix(r.URL.Path, "/policy") {
		body = []byte(policyJSON("enforce", 1, map[string]string{"tor": "block", "vpn": "flag"}))
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    r,
	}, nil
}

// FuzzHandle checks that whatever the visitor sends and whatever the API answers,
// only the guard's own X-IPScanner-* headers reach the upstream and failures pass.
func FuzzHandle(f *testing.F) {
	tor := verdictJSON("tor", "human", "tor", true, 90)
	f.Add(uint8(1), false, "203.0.113.9:443", "185.220.101.1", "X-IPScanner-Class", "human", "/", chrome, []byte(tor))
	f.Add(uint8(1), false, "10.0.0.2:443", "185.220.101.1", "x-ipscanner-action", "allow", "/login", chrome, []byte(tor))
	f.Add(uint8(1), true, "10.0.0.2:443", "84.128.0.1", "X-Ipscanner-Status", "ok", "/", chrome, []byte(verdictJSON("human", "human", "residential_clean", false, 3)))
	f.Add(uint8(4), false, "185.220.101.1:1", "", "X-IPSCANNER-SITE", "site_x", "/", "", []byte(`{"class":"human","network":{"country":"D\r\nX-Evil: 1"}}`))
	f.Add(uint8(0), false, "185.220.101.1:1", "", "Cookie", "c=1", "/", "curl/8", []byte(`not json`))
	f.Add(uint8(2), true, "[2001:db8::1]:1", "", "X-Ipscanner-Class", "", "/", chrome, []byte(`{"class":"vpn","mode":"monitor"}`))
	f.Fuzz(func(t *testing.T, preset uint8, site bool, remote, xff, forgedName, forgedValue, path, ua string, apiBody []byte) {
		cfg := Config{
			APIKey:         "pk_test_fuzz",
			APIURL:         "http://api.invalid",
			Mode:           ModeEnforce,
			BlockClasses:   []string{ClassTor, ClassVPN},
			TrustedProxies: fuzzTrusted[int(preset)%len(fuzzTrusted)],
			HTTPClient:     &http.Client{Transport: &fuzzTransport{body: apiBody}},
			Logger:         func(string) {},
		}
		if site {
			cfg.SiteID = testSite
		}
		g, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		r := fuzzRequest(remote, map[string][]string{
			"X-Forwarded-For":   {xff},
			"User-Agent":        {ua},
			"X-Ipscanner-Class": {"human"},
		})
		r.URL.Path = path
		r.Header[forgedName] = append(r.Header[forgedName], forgedValue)
		r.Header["x-ipscanner-action"] = []string{"allow"}
		trustedPeer := g.TrustedPeer(r)
		peer := remoteIP(r)

		w := httptest.NewRecorder()
		d, pass := g.Handle(w, r)

		if pass == d.Blocked() {
			t.Fatalf("pass %v with action %q", pass, d.Action)
		}
		if !pass && (w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Access denied")) {
			t.Fatalf("blocked without the block page: %d", w.Code)
		}
		if d.Status != StatusOK && d.Action != ActionAllow {
			t.Fatalf("status %q did not fail open: %q", d.Status, d.Action)
		}
		switch d.Status {
		case StatusOK, StatusError, StatusTimeout, StatusBackoff, StatusSkipped:
		default:
			t.Fatalf("status %q", d.Status)
		}
		if !trustedPeer && d.IP != peer {
			t.Fatalf("untrusted peer %q: visitor IP %q", remote, d.IP)
		}
		want := map[string]string{}
		for name, value := range d.Headers() {
			want[http.CanonicalHeaderKey(name)] = value
		}
		for name, values := range r.Header {
			if !strings.HasPrefix(http.CanonicalHeaderKey(name), HeaderPrefix) {
				continue
			}
			if len(values) != 1 || want[name] != values[0] {
				t.Fatalf("upstream got %s: %q, guard set %q", name, values, want[name])
			}
			if !validHeaderValue(values[0]) {
				t.Fatalf("upstream header %s: %q is not a valid header value", name, values[0])
			}
		}
		for name, value := range want {
			if r.Header.Get(name) != value {
				t.Fatalf("guard header %s missing", name)
			}
		}
	})
}
