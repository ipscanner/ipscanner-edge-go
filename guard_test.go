package edge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testSite = "site_unittest000000000001"
	torIP    = "185.220.101.1"
	homeIP   = "84.128.0.1"
	vpnIP    = "185.217.69.166"
	botIP    = "66.249.66.1"
	chrome   = "Mozilla/5.0 (Macintosh) Chrome/141.0.0.0 Safari/537.36"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type recorded struct {
	method  string
	path    string
	headers http.Header
	body    map[string]interface{}
}

type fakeAPI struct {
	mu       sync.Mutex
	calls    []recorded
	verdicts map[string]string
	policy   string // policy JSON, "" for 404
	mode     string // top level edge check mode, "" to leave it out
	edgeCode int
	polCode  int
	delay    time.Duration
	srv      *httptest.Server
}

func newFakeAPI(t *testing.T) *fakeAPI {
	f := &fakeAPI{verdicts: map[string]string{
		homeIP: verdictJSON("human", "human", "residential_clean", false, 3),
		torIP:  verdictJSON("tor", "human", "tor", true, 90),
		vpnIP:  verdictJSON("vpn", "human", "vpn", true, 60),
		botIP:  `{"class":"verified_bot","agent":{"class":"known_bot","confidence":0.99,"action":"allow","signals":{"allowlist_verified":true}},"network":{"networkClass":"hosting","anonymized":false,"riskScore":5,"country":"US"},"site":null}`,
	}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func verdictJSON(class, agentClass, network string, anonymized bool, risk int) string {
	return fmt.Sprintf(`{"class":%q,"agent":{"class":%q,"confidence":0.9,"action":"allow","signals":{"network_origin":%q}},"network":{"networkClass":%q,"anonymized":%t,"riskScore":%d,"country":"DE","asn":3320},"site":null}`,
		class, agentClass, network, network, anonymized, risk)
}

func (f *fakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	var body map[string]interface{}
	_ = json.Unmarshal(raw, &body)
	f.mu.Lock()
	f.calls = append(f.calls, recorded{method: r.Method, path: r.URL.Path, headers: r.Header.Clone(), body: body})
	delay, edgeCode, polCode, policy, mode := f.delay, f.edgeCode, f.polCode, f.policy, f.mode
	verdict := f.verdicts[fmt.Sprint(body["ip"])]
	f.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-r.Context().Done():
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	switch {
	case r.URL.Path == "/v1/edge/check":
		if edgeCode != 0 {
			w.WriteHeader(edgeCode)
			fmt.Fprint(w, `{"error":"nope"}`)
			return
		}
		if verdict == "" {
			verdict = verdictJSON("human", "human", "residential_clean", false, 1)
		}
		if site, _ := body["site"].(string); site != "" && policy != "" {
			var p map[string]interface{}
			_ = json.Unmarshal([]byte(policy), &p)
			verdict = strings.Replace(verdict, `"site":null`, fmt.Sprintf(`"site":{"id":%q,"mode":%q,"policyVersion":%v}`, site, p["mode"], p["version"]), 1)
		}
		if mode != "" {
			verdict = fmt.Sprintf(`{"mode":%q,`, mode) + verdict[1:]
		}
		fmt.Fprint(w, verdict)
	case strings.HasPrefix(r.URL.Path, "/v1/sites/") && strings.HasSuffix(r.URL.Path, "/policy"):
		if polCode != 0 {
			w.WriteHeader(polCode)
			return
		}
		if policy == "" {
			w.WriteHeader(404)
			fmt.Fprint(w, `{"error":"unknown_site"}`)
			return
		}
		fmt.Fprint(w, policy)
	default:
		w.WriteHeader(404)
	}
}

func (f *fakeAPI) set(fn func(f *fakeAPI)) {
	f.mu.Lock()
	fn(f)
	f.mu.Unlock()
}

func (f *fakeAPI) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, c := range f.calls {
		if path == "" || c.path == path || (path == "policy" && strings.HasSuffix(c.path, "/policy")) {
			n++
		}
	}
	return n
}

func (f *fakeAPI) last() recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func policyJSON(mode string, version int, actions map[string]string) string {
	b, _ := json.Marshal(map[string]interface{}{"site": testSite, "mode": mode, "policy": actions, "version": version})
	return string(b)
}

func newGuard(t *testing.T, f *fakeAPI, cfg Config) (*Guard, *clock) {
	t.Helper()
	cfg.APIKey = "pk_test_unit"
	cfg.APIURL = f.srv.URL
	if cfg.Source == "" {
		cfg.Source, cfg.Client, cfg.Version = "traefik", "traefik", "0.1.0"
	}
	if cfg.Logger == nil {
		cfg.Logger = func(string) {}
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	clk := &clock{t: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
	g.now = clk.Now
	return g, clk
}

func visitor(ip string) Visitor {
	return Visitor{IP: ip, UserAgent: chrome, Method: "GET", Path: "/"}
}

func check(g *Guard, ip string) Decision {
	return g.CheckVisitor(context.Background(), visitor(ip))
}

func TestRequestShape(t *testing.T) {
	f := newFakeAPI(t)
	g, _ := newGuard(t, f, Config{SiteID: testSite})
	f.set(func(f *fakeAPI) { f.policy = policyJSON("monitor", 1, nil) })

	r := httptest.NewRequest("GET", "http://example.test/page?q=1", nil)
	r.Header.Set("User-Agent", chrome)
	r.Header.Set("Accept-Language", "de-DE")
	r.Header.Set("Sec-Ch-Ua-Platform", `"macOS"`)
	r.Header.Set("Cookie", "secret=1")
	r.Header.Set("X-Request-Id", "req-123")
	d := g.Check(context.Background(), r, homeIP)
	if d.Status != StatusOK {
		t.Fatalf("status %s", d.Status)
	}

	f.mu.Lock()
	calls := append([]recorded(nil), f.calls...)
	f.mu.Unlock()
	var edge, pol *recorded
	for i := range calls {
		c := calls[i]
		if c.path == "/v1/edge/check" {
			edge = &c
		} else {
			pol = &c
		}
	}
	if edge == nil || pol == nil {
		t.Fatalf("calls %+v", calls)
	}
	if edge.method != "POST" || pol.method != "GET" || pol.path != "/v1/sites/"+testSite+"/policy" {
		t.Fatalf("methods %s %s %s", edge.method, pol.method, pol.path)
	}
	for _, c := range []*recorded{edge, pol} {
		if c.headers.Get("Authorization") != "Bearer pk_test_unit" ||
			c.headers.Get("User-Agent") != "ipscanner-traefik/0.1.0" ||
			c.headers.Get("X-IPScanner-Source") != "traefik" ||
			c.headers.Get("Accept") != "application/json" {
			t.Fatalf("headers %v", c.headers)
		}
	}
	if edge.headers.Get("Content-Type") != "application/json" || pol.headers.Get("Content-Type") != "" {
		t.Fatal("content type")
	}
	b := edge.body
	if b["site"] != testSite || b["ip"] != homeIP || b["user_agent"] != chrome || b["request_id"] != "req-123" {
		t.Fatalf("body %v", b)
	}
	if _, ok := b["ja4"]; ok {
		t.Fatal("ja4 sent without a value")
	}
	h, _ := b["headers"].(map[string]interface{})
	if len(h) != 2 || h["accept-language"] != "de-DE" || h["sec-ch-ua-platform"] != `"macOS"` {
		t.Fatalf("signal headers %v", h)
	}
}

func TestNoSiteOmitsSite(t *testing.T) {
	f := newFakeAPI(t)
	g, _ := newGuard(t, f, Config{})
	check(g, homeIP)
	if _, ok := f.last().body["site"]; ok {
		t.Fatal("site sent without SiteID")
	}
	if f.count("policy") != 0 {
		t.Fatal("policy fetched without SiteID")
	}
}

func TestSitePolicyActions(t *testing.T) {
	f := newFakeAPI(t)
	f.policy = policyJSON("enforce", 4, map[string]string{"tor": "block", "vpn": "flag", "verified_bot": "block", "hosting": "block"})
	g, _ := newGuard(t, f, Config{SiteID: testSite})

	cases := []struct {
		ip, class, action, outcome string
	}{
		{homeIP, "human", "allow", "allow"},
		{torIP, "tor", "block", "block"},
		{vpnIP, "vpn", "flag", "flag"},
		{botIP, "verified_bot", "allow", "allow"},
	}
	for _, c := range cases {
		d := check(g, c.ip)
		if d.Status != StatusOK || d.Class != c.class || d.Action != c.action || d.Outcome != c.outcome || d.Mode != ModeEnforce {
			t.Fatalf("%s: %+v", c.ip, d)
		}
		if d.PolicyVersion != 4 {
			t.Fatalf("policy version %d", d.PolicyVersion)
		}
	}
	if n := f.count("policy"); n != 1 {
		t.Fatalf("policy fetched %d times", n)
	}
}

func TestSiteMatchesTrafficClassOnly(t *testing.T) {
	f := newFakeAPI(t)
	f.verdicts[homeIP] = verdictJSON("malicious_automation", "malicious_automation", "vpn", true, 80)
	f.policy = policyJSON("enforce", 1, map[string]string{"vpn": "block"})
	g, _ := newGuard(t, f, Config{SiteID: testSite})
	if d := check(g, homeIP); d.Blocked() {
		t.Fatalf("site policy matched the network class: %+v", d)
	}
}

func TestAllowlistVerifiedAlwaysPasses(t *testing.T) {
	f := newFakeAPI(t)
	f.verdicts[homeIP] = `{"class":"ai_agent","agent":{"class":"ai_agent","confidence":0.9,"action":"allow","signals":{"allowlist_verified":true}},"network":null,"site":null}`
	f.policy = policyJSON("enforce", 1, map[string]string{"ai_agent": "block"})
	g, _ := newGuard(t, f, Config{SiteID: testSite})
	if d := check(g, homeIP); d.Blocked() || d.Outcome != "allow" {
		t.Fatalf("%+v", d)
	}
}

func TestMonitorNeverBlocks(t *testing.T) {
	f := newFakeAPI(t)
	f.policy = policyJSON("monitor", 1, map[string]string{"tor": "block", "vpn": "flag"})
	g, _ := newGuard(t, f, Config{SiteID: testSite})
	d := check(g, torIP)
	if d.Blocked() || d.Action != "allow" || d.Outcome != "would_block" || d.Mode != ModeMonitor {
		t.Fatalf("%+v", d)
	}
	d = check(g, vpnIP)
	if d.Action != "allow" || d.Outcome != "would_flag" {
		t.Fatalf("%+v", d)
	}
}

func TestModeMonitorOverridesSite(t *testing.T) {
	f := newFakeAPI(t)
	f.policy = policyJSON("enforce", 1, map[string]string{"tor": "block"})
	g, _ := newGuard(t, f, Config{SiteID: testSite, Mode: "monitor"})
	if d := check(g, torIP); d.Blocked() || d.Outcome != "would_block" {
		t.Fatalf("%+v", d)
	}
	f2 := newFakeAPI(t)
	f2.policy = policyJSON("monitor", 1, map[string]string{"tor": "block"})
	g2, _ := newGuard(t, f2, Config{SiteID: testSite, Mode: "enforce"})
	if d := check(g2, torIP); d.Blocked() {
		t.Fatalf("enforce config overrode a monitor site: %+v", d)
	}
}

func TestNoPolicy404(t *testing.T) {
	f := newFakeAPI(t)
	g, clk := newGuard(t, f, Config{SiteID: testSite})
	d := check(g, torIP)
	if d.Status != StatusOK || d.Blocked() || d.PolicySource != "none" || d.Outcome != "allow" {
		t.Fatalf("%+v", d)
	}
	clk.Add(10 * time.Second)
	check(g, homeIP)
	if n := f.count("policy"); n != 1 {
		t.Fatalf("404 not cached: %d policy calls", n)
	}
}

func TestPolicyTTLAndStale(t *testing.T) {
	f := newFakeAPI(t)
	f.policy = policyJSON("enforce", 1, map[string]string{"tor": "allow"})
	g, clk := newGuard(t, f, Config{SiteID: testSite, PolicyTTL: 30 * time.Second})

	if d := check(g, torIP); d.Blocked() || d.PolicySource != "fetch" {
		t.Fatalf("%+v", d)
	}
	f.set(func(f *fakeAPI) { f.policy = policyJSON("enforce", 2, map[string]string{"tor": "block"}) })
	clk.Add(10 * time.Second)
	if d := check(g, torIP); d.Blocked() || d.PolicySource != "cache" {
		t.Fatalf("policy refreshed before the TTL: %+v", d)
	}
	clk.Add(21 * time.Second)
	if d := check(g, torIP); !d.Blocked() || d.PolicyVersion != 2 || d.PolicySource != "fetch" {
		t.Fatalf("policy change not picked up after the TTL: %+v", d)
	}

	f.set(func(f *fakeAPI) { f.polCode = 500 })
	clk.Add(31 * time.Second)
	before := f.count("policy")
	if d := check(g, torIP); !d.Blocked() || d.PolicySource != "stale" {
		t.Fatalf("stale policy not used: %+v", d)
	}
	clk.Add(2 * time.Second)
	check(g, torIP)
	if n := f.count("policy") - before; n != 1 {
		t.Fatalf("retry gap ignored: %d calls", n)
	}
	clk.Add(4 * time.Second)
	check(g, torIP)
	if n := f.count("policy") - before; n != 2 {
		t.Fatalf("no retry after the gap: %d calls", n)
	}

	clk.Add(25 * time.Hour)
	if d := check(g, torIP); d.Blocked() || d.PolicySource != "none" {
		t.Fatalf("policy older than 24h used: %+v", d)
	}
}

func TestPolicyVersionFromVerdict(t *testing.T) {
	f := newFakeAPI(t)
	f.policy = policyJSON("enforce", 1, map[string]string{"tor": "allow"})
	g, clk := newGuard(t, f, Config{SiteID: testSite, PolicyTTL: time.Minute})
	check(g, homeIP)
	f.set(func(f *fakeAPI) { f.policy = policyJSON("enforce", 2, map[string]string{"tor": "block"}) })
	clk.Add(6 * time.Second)
	if d := check(g, torIP); !d.Blocked() || d.PolicyVersion != 2 {
		t.Fatalf("%+v", d)
	}
}

func TestNoSiteConfig(t *testing.T) {
	f := newFakeAPI(t)
	f.verdicts[homeIP] = verdictJSON("malicious_automation", "malicious_automation", "residential_clean", false, 70)
	f.verdicts["93.184.216.34"] = verdictJSON("malicious_automation", "malicious_automation", "vpn", true, 70)

	g, _ := newGuard(t, f, Config{})
	if d := check(g, homeIP); d.Blocked() || d.Outcome != "would_block" || d.Mode != ModeMonitor || d.PolicySource != "config" {
		t.Fatalf("default monitor: %+v", d)
	}

	g, _ = newGuard(t, f, Config{Mode: "enforce"})
	if d := check(g, homeIP); !d.Blocked() {
		t.Fatalf("enforce default classes: %+v", d)
	}
	if d := check(g, torIP); d.Blocked() {
		t.Fatalf("tor blocked by default: %+v", d)
	}

	g, _ = newGuard(t, f, Config{Mode: "enforce", BlockClasses: []string{"vpn"}})
	if d := check(g, "93.184.216.34"); !d.Blocked() || d.Class != "malicious_automation" {
		t.Fatalf("network class: %+v", d)
	}
	if d := check(g, homeIP); d.Blocked() {
		t.Fatalf("malicious_automation blocked with only vpn listed: %+v", d)
	}

	g, _ = newGuard(t, f, Config{Mode: "enforce", BlockClasses: []string{"none"}})
	if d := check(g, homeIP); d.Blocked() {
		t.Fatalf("none: %+v", d)
	}

	g, _ = newGuard(t, f, Config{Mode: "enforce", BlockClasses: []string{"hosting"}})
	if d := check(g, botIP); d.Blocked() {
		t.Fatalf("verified crawler blocked: %+v", d)
	}
}

func TestAccountMode(t *testing.T) {
	cases := []struct {
		name, mode  string
		site, block bool
	}{
		{"no site, monitor", "monitor", false, false},
		{"no site, enforce", "enforce", false, true},
		{"no site, absent", "", false, true},
		{"site, monitor", "monitor", true, false},
		{"site, enforce", "enforce", true, true},
		{"site, absent", "", true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFakeAPI(t)
			f.mode = c.mode
			cfg := Config{Mode: "enforce", BlockClasses: []string{"tor"}}
			if c.site {
				f.policy = policyJSON("enforce", 1, map[string]string{"tor": "block"})
				cfg = Config{SiteID: testSite}
			}
			g, _ := newGuard(t, f, cfg)
			for i := 0; i < 2; i++ {
				d := check(g, torIP)
				if d.Status != StatusOK || d.Cached != (i == 1) {
					t.Fatalf("check %d: %+v", i, d)
				}
				if c.block && (!d.Blocked() || d.Mode != ModeEnforce || d.Outcome != ActionBlock) {
					t.Fatalf("check %d not blocked: %+v", i, d)
				}
				if !c.block && (d.Blocked() || d.Action != ActionAllow || d.Mode != ModeMonitor || d.Outcome != "would_block") {
					t.Fatalf("check %d blocked on a monitor account: %+v", i, d)
				}
			}
		})
	}
}

func TestAccountModeMonitorHandle(t *testing.T) {
	f := newFakeAPI(t)
	f.mode = "monitor"
	var mu sync.Mutex
	var lines []string
	g, _ := newGuard(t, f, Config{Mode: "enforce", BlockClasses: []string{"tor"}, Debug: true, Logger: func(line string) {
		mu.Lock()
		lines = append(lines, line)
		mu.Unlock()
	}})
	r := httptest.NewRequest("GET", "http://example.test/", nil)
	r.RemoteAddr = torIP + ":1234"
	r.Header.Set("User-Agent", chrome)
	w := httptest.NewRecorder()
	if _, next := g.Handle(w, r); !next || w.Code != 200 {
		t.Fatalf("blocked on a monitor account: %v %d", next, w.Code)
	}
	if got := r.Header.Get("X-IPScanner-Action"); got != "would_block" {
		t.Fatalf("upstream action %q", got)
	}
	if got := w.Header().Get("X-IPScanner-Action"); got != "would_block" {
		t.Fatalf("debug action %q", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(lines) == 0 || !strings.Contains(lines[len(lines)-1], `"decision":"would_block"`) || !strings.Contains(lines[len(lines)-1], `"mode":"monitor"`) {
		t.Fatalf("log %v", lines)
	}
}

func TestAccountModeCachedWithVerdict(t *testing.T) {
	f := newFakeAPI(t)
	f.mode = "monitor"
	g, clk := newGuard(t, f, Config{Mode: "enforce", BlockClasses: []string{"tor"}, CacheTTL: time.Minute})
	if d := check(g, torIP); d.Blocked() {
		t.Fatalf("%+v", d)
	}
	f.set(func(f *fakeAPI) { f.mode = "enforce" })
	if d := check(g, torIP); !d.Cached || d.Blocked() || d.Outcome != "would_block" {
		t.Fatalf("cached verdict lost its mode: %+v", d)
	}
	clk.Add(61 * time.Second)
	if d := check(g, torIP); d.Cached || !d.Blocked() {
		t.Fatalf("new mode not picked up after the cache TTL: %+v", d)
	}

	f.set(func(f *fakeAPI) { f.mode = "monitor" })
	clk.Add(61 * time.Second)
	if d := check(g, torIP); d.Cached || d.Blocked() {
		t.Fatalf("downgrade not picked up after the cache TTL: %+v", d)
	}
}

func TestVerdictCache(t *testing.T) {
	f := newFakeAPI(t)
	g, clk := newGuard(t, f, Config{CacheTTL: time.Minute})
	if d := check(g, homeIP); d.Cached {
		t.Fatal("first check cached")
	}
	if d := check(g, homeIP); !d.Cached || d.Status != StatusOK {
		t.Fatalf("second check: %+v", d)
	}
	if n := f.count("/v1/edge/check"); n != 1 {
		t.Fatalf("%d edge calls", n)
	}
	v := visitor(homeIP)
	v.UserAgent = "other"
	g.CheckVisitor(context.Background(), v)
	if n := f.count("/v1/edge/check"); n != 2 {
		t.Fatalf("user agent not in the cache key: %d calls", n)
	}
	clk.Add(61 * time.Second)
	check(g, homeIP)
	if n := f.count("/v1/edge/check"); n != 3 {
		t.Fatalf("expired verdict reused: %d calls", n)
	}
}

func TestVerdictCacheBounded(t *testing.T) {
	c := newVerdictCache(3, time.Minute)
	now := time.Now()
	for i := 0; i < 5; i++ {
		c.set(fmt.Sprint(i), &Verdict{Class: "human"}, now)
	}
	if c.len() != 3 {
		t.Fatalf("len %d", c.len())
	}
	if c.get("0", now) != nil || c.get("1", now) != nil || c.get("4", now) == nil {
		t.Fatal("oldest entries not evicted")
	}
	c.get("2", now)
	c.set("5", &Verdict{}, now)
	if c.get("2", now) == nil || c.get("3", now) != nil {
		t.Fatal("not LRU")
	}
}

func TestConcurrentVisitorsShareOneCall(t *testing.T) {
	f := newFakeAPI(t)
	f.delay = 100 * time.Millisecond
	g, _ := newGuard(t, f, Config{})
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d := check(g, homeIP); d.Status != StatusOK {
				t.Errorf("status %s", d.Status)
			}
		}()
	}
	wg.Wait()
	if n := f.count("/v1/edge/check"); n != 1 {
		t.Fatalf("%d edge calls", n)
	}
}

func TestFailOpenTimeoutAndBackoff(t *testing.T) {
	f := newFakeAPI(t)
	f.delay = 2 * time.Second
	g, clk := newGuard(t, f, Config{Timeout: 150 * time.Millisecond, Mode: "enforce", BlockClasses: []string{"tor"}})
	start := time.Now()
	d := check(g, torIP)
	if d.Status != StatusTimeout || d.Blocked() || time.Since(start) > time.Second {
		t.Fatalf("%+v after %s", d, time.Since(start))
	}
	// The detached call fails at its own timeout and sets the backoff.
	deadline := time.Now().Add(2 * time.Second)
	for g.State().BackoffUntil.IsZero() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	before := f.count("")
	if d := check(g, torIP); d.Status != StatusBackoff || d.Blocked() {
		t.Fatalf("%+v", d)
	}
	if f.count("") != before {
		t.Fatal("API called during backoff")
	}
	f.set(func(f *fakeAPI) { f.delay = 0 })
	clk.Add(31 * time.Second)
	if d := check(g, torIP); d.Status != StatusOK || !d.Blocked() {
		t.Fatalf("no recovery after the backoff: %+v", d)
	}
}

func TestFailOpenStatusCodes(t *testing.T) {
	cases := []struct {
		code  int
		pause time.Duration
	}{
		{500, 30 * time.Second},
		{401, 5 * time.Minute},
		{402, 5 * time.Minute},
		{403, 5 * time.Minute},
		{429, 5 * time.Minute},
		{400, 0},
	}
	for _, c := range cases {
		f := newFakeAPI(t)
		f.edgeCode = c.code
		g, clk := newGuard(t, f, Config{Mode: "enforce", BlockClasses: []string{"tor"}})
		if d := check(g, torIP); d.Status != StatusError || d.Blocked() {
			t.Fatalf("%d: %+v", c.code, d)
		}
		st := g.State()
		if st.LastCode != c.code {
			t.Fatalf("%d: last code %d", c.code, st.LastCode)
		}
		if got := st.BackoffUntil.Sub(clk.Now()); c.pause > 0 && got != c.pause {
			t.Fatalf("%d: backoff %s", c.code, got)
		}
		if c.pause == 0 && !st.BackoffUntil.IsZero() {
			t.Fatalf("%d: backoff set", c.code)
		}
	}
}

func TestFailOpenDeadAPI(t *testing.T) {
	g, err := New(Config{APIKey: "pk_test_x", APIURL: "http://127.0.0.1:1", Mode: "enforce", BlockClasses: []string{"tor"}, Logger: func(string) {}})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	d := check(g, torIP)
	if d.Status != StatusError || d.Blocked() || time.Since(start) > time.Second {
		t.Fatalf("%+v after %s", d, time.Since(start))
	}
	if d := check(g, torIP); d.Status != StatusBackoff {
		t.Fatalf("%+v", d)
	}
}

func TestBadResponseFailsOpen(t *testing.T) {
	f := newFakeAPI(t)
	f.verdicts[torIP] = `{"unexpected":true}`
	g, _ := newGuard(t, f, Config{Mode: "enforce", BlockClasses: []string{"tor"}})
	if d := check(g, torIP); d.Status != StatusError || d.Blocked() {
		t.Fatalf("%+v", d)
	}
}

func TestSkips(t *testing.T) {
	f := newFakeAPI(t)
	g, _ := newGuard(t, f, Config{})
	for name, v := range map[string]Visitor{
		"options":  {IP: torIP, Method: "OPTIONS", Path: "/"},
		"asset":    {IP: torIP, Method: "GET", Path: "/static/App.CSS"},
		"robots":   {IP: torIP, Method: "GET", Path: "/robots.txt"},
		"private":  {IP: "192.168.1.10", Method: "GET", Path: "/"},
		"loopback": {IP: "::1", Method: "GET", Path: "/"},
		"no ip":    {IP: "", Method: "GET", Path: "/"},
	} {
		if d := g.CheckVisitor(context.Background(), v); d.Status != StatusSkipped || d.Action != "allow" {
			t.Fatalf("%s: %+v", name, d)
		}
	}
	if f.count("") != 0 {
		t.Fatal("API called for a skipped request")
	}

	g, _ = newGuard(t, f, Config{SkipPaths: "none"})
	if d := g.CheckVisitor(context.Background(), Visitor{IP: torIP, Method: "GET", Path: "/app.css"}); d.Status != StatusOK {
		t.Fatalf("none: %+v", d)
	}
	g, _ = newGuard(t, f, Config{SkipPaths: "^/health"})
	if d := g.CheckVisitor(context.Background(), Visitor{IP: torIP, Method: "GET", Path: "/HEALTHZ"}); d.Status != StatusSkipped {
		t.Fatalf("custom: %+v", d)
	}

	nokey, err := New(Config{Logger: func(string) {}})
	if err != nil {
		t.Fatal(err)
	}
	if d := check(nokey, torIP); d.Status != StatusSkipped || nokey.Enabled() {
		t.Fatalf("no key: %+v", d)
	}
}

func TestHandle(t *testing.T) {
	f := newFakeAPI(t)
	f.policy = policyJSON("enforce", 1, map[string]string{"tor": "block", "vpn": "flag"})
	g, _ := newGuard(t, f, Config{SiteID: testSite, TrustedProxies: []string{"10.0.0.0/8"}})

	r := httptest.NewRequest("GET", "http://example.test/", nil)
	r.RemoteAddr = "10.0.0.2:1234"
	r.Header.Set("X-Forwarded-For", torIP)
	r.Header.Set("User-Agent", chrome)
	w := httptest.NewRecorder()
	d, next := g.Handle(w, r)
	if next || w.Code != 403 || !strings.Contains(w.Body.String(), d.RequestID) || d.RequestID == "" {
		t.Fatalf("%v %d %s", next, w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-IPScanner-Status") != "" {
		t.Fatalf("response headers %v", w.Header())
	}

	r = httptest.NewRequest("GET", "http://example.test/", nil)
	r.RemoteAddr = vpnIP + ":1234"
	r.Header.Set("X-IPScanner-Action", "allow")
	r.Header.Set("X-Ipscanner-Spoofed", "1")
	w = httptest.NewRecorder()
	d, next = g.Handle(w, r)
	if !next || w.Code != 200 {
		t.Fatalf("%v %d", next, w.Code)
	}
	want := map[string]string{
		"X-IPScanner-Status":        "ok",
		"X-IPScanner-Class":         "vpn",
		"X-IPScanner-Action":        "flag",
		"X-IPScanner-Network-Class": "vpn",
		"X-IPScanner-Anonymized":    "true",
		"X-IPScanner-Risk":          "60",
		"X-IPScanner-Country":       "DE",
		"X-IPScanner-Site":          testSite,
	}
	for k, v := range want {
		if got := r.Header.Get(k); got != v {
			t.Fatalf("%s = %q, want %q", k, got, v)
		}
	}
	if r.Header.Get("X-Ipscanner-Spoofed") != "" {
		t.Fatal("spoofed header kept")
	}

	g, _ = newGuard(t, f, Config{SiteID: testSite, Debug: true})
	r = httptest.NewRequest("GET", "http://example.test/", nil)
	r.RemoteAddr = homeIP + ":1234"
	w = httptest.NewRecorder()
	g.Handle(w, r)
	if w.Header().Get("X-IPScanner-Status") != "ok" || w.Header().Get("X-IPScanner-Class") != "human" || w.Header().Get("X-IPScanner-Action") != "allow" {
		t.Fatalf("debug headers %v", w.Header())
	}
}

func TestHeadersOnFailure(t *testing.T) {
	d := Decision{Status: StatusTimeout, Action: "allow", Outcome: "allow"}
	h := d.Headers()
	if len(h) != 1 || h["X-IPScanner-Status"] != "timeout" {
		t.Fatalf("%v", h)
	}
	dh := d.DebugHeaders()
	if len(dh) != 1 {
		t.Fatalf("%v", dh)
	}
}

func TestBlockPageEscapes(t *testing.T) {
	page := string(BlockPage(`<script>`, `a & b`))
	if strings.Contains(page, "<script>") || !strings.Contains(page, "&lt;script&gt;") || !strings.Contains(page, "a &amp; b") {
		t.Fatal(page)
	}
}

func TestRequestIDFormat(t *testing.T) {
	id := newRequestID()
	if len(id) != 36 || id[14] != '4' {
		t.Fatal(id)
	}
}
