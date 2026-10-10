//go:build e2e

// End to end tests against a running IPScanner API. See test/e2e/run.sh.
//
//	IPSCANNER_API_URL   API base URL (default http://localhost:3050)
//	IPSCANNER_KEY_FILE  file holding the API key (or IPSCANNER_API_KEY)
//	IPSCANNER_E2E_SITE_HELPER  node script that upserts a site and lists
//	                    request_log rows; site scenarios are skipped without it
//	IPSCANNER_E2E_SITE  site id (default site_edgegoe2e00000000001)
package edge_test

import (
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	edge "github.com/ipscanner/ipscanner-edge-go"
)

const (
	e2eTor         = "185.220.101.1"
	e2eVPN         = "185.217.69.166"
	e2eResidential = "84.128.0.1"
	e2eGooglebotIP = "66.249.66.1"
	e2eChrome      = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
	e2eHeadless    = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/141.0.0.0 Safari/537.36"
	e2eGooglebot   = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	e2eSource      = "forward_auth"
)

func e2eEnv(t *testing.T) (apiURL, key string) {
	t.Helper()
	apiURL = os.Getenv("IPSCANNER_API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:3050"
	}
	key = strings.TrimSpace(os.Getenv("IPSCANNER_API_KEY"))
	if file := os.Getenv("IPSCANNER_KEY_FILE"); key == "" && file != "" {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		key = strings.TrimSpace(string(raw))
	}
	if key == "" {
		t.Skip("set IPSCANNER_KEY_FILE or IPSCANNER_API_KEY")
	}
	return apiURL, key
}

func e2eSite() string {
	if s := os.Getenv("IPSCANNER_E2E_SITE"); s != "" {
		return s
	}
	return "site_edgegoe2e00000000001"
}

func helper(t *testing.T, args ...string) string {
	t.Helper()
	script := os.Getenv("IPSCANNER_E2E_SITE_HELPER")
	if script == "" {
		t.Skip("set IPSCANNER_E2E_SITE_HELPER")
	}
	out, err := exec.Command("node", append([]string{script}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("helper %v: %v %s", args, err, out)
	}
	return string(out)
}

type siteRow struct {
	PolicyVersion int    `json:"policy_version"`
	ClientVersion string `json:"client_version"`
}

func setSite(t *testing.T, mode string, policy map[string]string) siteRow {
	t.Helper()
	raw, _ := json.Marshal(policy)
	var row siteRow
	out := helper(t, e2eSite(), "forward_auth", mode, string(raw))
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &row); err != nil {
		t.Fatalf("helper output %q", out)
	}
	return row
}

type logRow struct {
	Source       string `json:"source"`
	Endpoint     string `json:"endpoint"`
	TrafficClass string `json:"traffic_class"`
	Action       string `json:"action"`
	Site         string `json:"site"`
	CreatedAt    string `json:"created_at"`
}

func rows(t *testing.T, n int) []logRow {
	t.Helper()
	var out []logRow
	raw := helper(t, "rows", e2eSource, strconv.Itoa(n))
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("rows output %q", raw)
	}
	return out
}

var warmOnce sync.Once

// warm makes one check with a long timeout, so a cold API (new connections
// to its database) does not turn the first scenario into a fail open.
func warm(t *testing.T) {
	warmOnce.Do(func() {
		g := guard(t, edge.Config{SiteID: e2eSite(), Timeout: 10 * time.Second})
		g.CheckVisitor(context.Background(), edge.Visitor{IP: "84.128.0.2", UserAgent: uniqueUA(e2eChrome), Method: "GET", Path: "/"})
	})
}

func guard(t *testing.T, cfg edge.Config) *edge.Guard {
	t.Helper()
	apiURL, key := e2eEnv(t)
	if cfg.APIURL == "" {
		cfg.APIURL = apiURL
	}
	cfg.APIKey = key
	cfg.Source, cfg.Client, cfg.Version = e2eSource, "forward-auth", edge.Version
	cfg.Logger = func(line string) { t.Log(line) }
	g, err := edge.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// uniqueUA keeps verdicts of earlier runs out of the API's own caches.
func uniqueUA(base string) string {
	return base + " e2e/" + strconv.FormatInt(time.Now().UnixNano(), 36) + strconv.Itoa(rand.Intn(1000))
}

func request(remote, xff, ua string) *http.Request {
	r := httptest.NewRequest("GET", "http://example.test/page", nil)
	r.RemoteAddr = remote + ":40000"
	if strings.Contains(remote, ":") {
		r.RemoteAddr = "[" + remote + "]:40000"
	}
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	r.Header.Set("User-Agent", ua)
	r.Header.Set("Accept", "text/html")
	r.Header.Set("Accept-Language", "en-US,en;q=0.9")
	return r
}

func TestE2ESiteEnforce(t *testing.T) {
	setSite(t, "enforce", map[string]string{"tor": "block", "vpn": "flag"})
	g := guard(t, edge.Config{SiteID: e2eSite(), PolicyTTL: 2 * time.Second, Debug: true})
	warm(t)

	// Residential visitor: allowed, headers for the upstream.
	r := request(e2eResidential, "", uniqueUA(e2eChrome))
	w := httptest.NewRecorder()
	d, next := g.Handle(w, r)
	if !next || d.Status != "ok" || d.Blocked() || d.Mode != "enforce" || d.PolicySource != "fetch" {
		t.Fatalf("residential: %+v", d)
	}
	if r.Header.Get("X-IPScanner-Status") != "ok" || r.Header.Get("X-IPScanner-Site") != e2eSite() || w.Header().Get("X-IPScanner-Class") == "" {
		t.Fatalf("headers %v / %v", r.Header, w.Header())
	}
	t.Logf("residential: class=%s outcome=%s network=%s", d.Class, d.Outcome, r.Header.Get("X-IPScanner-Network-Class"))

	// Tor: 403.
	r = request(e2eTor, "", uniqueUA(e2eChrome))
	w = httptest.NewRecorder()
	d, next = g.Handle(w, r)
	if next || w.Code != 403 || d.Class != "tor" || d.Outcome != "block" {
		t.Fatalf("tor: %+v code=%d", d, w.Code)
	}

	// VPN: flagged, passes with the flag header.
	r = request(e2eVPN, "", uniqueUA(e2eChrome))
	w = httptest.NewRecorder()
	d, next = g.Handle(w, r)
	if !next || d.Class != "vpn" || d.Action != "flag" || r.Header.Get("X-IPScanner-Action") != "flag" {
		t.Fatalf("vpn: %+v", d)
	}

	// Verified crawler passes whatever the policy.
	setSite(t, "enforce", map[string]string{"tor": "block", "vpn": "flag", "hosting": "block", "verified_bot": "block"})
	time.Sleep(2100 * time.Millisecond)
	r = request(e2eGooglebotIP, "", e2eGooglebot)
	w = httptest.NewRecorder()
	d, next = g.Handle(w, r)
	if !next || d.Class != "verified_bot" || d.Blocked() {
		t.Fatalf("googlebot: %+v", d)
	}
}

func TestE2EMonitorNeverBlocks(t *testing.T) {
	setSite(t, "monitor", map[string]string{"tor": "block", "vpn": "block"})
	g := guard(t, edge.Config{SiteID: e2eSite()})
	for _, ip := range []string{e2eTor, e2eVPN} {
		w := httptest.NewRecorder()
		d, next := g.Handle(w, request(ip, "", uniqueUA(e2eChrome)))
		if !next || w.Code != 200 || d.Mode != "monitor" || d.Outcome != "would_block" {
			t.Fatalf("%s: %+v", ip, d)
		}
	}
}

func TestE2EPolicyChange(t *testing.T) {
	setSite(t, "enforce", map[string]string{"tor": "allow"})
	g := guard(t, edge.Config{SiteID: e2eSite(), PolicyTTL: 2 * time.Second})
	ua := uniqueUA(e2eChrome)
	if d := g.CheckVisitor(context.Background(), edge.Visitor{IP: e2eTor, UserAgent: ua, Method: "GET", Path: "/"}); d.Blocked() || d.Status != "ok" {
		t.Fatalf("before: %+v", d)
	}
	row := setSite(t, "enforce", map[string]string{"tor": "block"})
	d := g.CheckVisitor(context.Background(), edge.Visitor{IP: e2eTor, UserAgent: ua, Method: "GET", Path: "/"})
	if d.Blocked() || !d.Cached {
		t.Fatalf("policy changed before the TTL: %+v", d)
	}
	time.Sleep(2100 * time.Millisecond)
	d = g.CheckVisitor(context.Background(), edge.Visitor{IP: e2eTor, UserAgent: ua, Method: "GET", Path: "/"})
	if !d.Blocked() || d.PolicyVersion != row.PolicyVersion || d.PolicySource != "fetch" {
		t.Fatalf("after the TTL: %+v (want version %d)", d, row.PolicyVersion)
	}
}

// The API writes request_log in batches, usually within 5 seconds.
const flushWait = 30 * time.Second

// newerThan keeps this site's rows logged after since. created_at is the
// API's clock, which is this machine's for a local API. Other clients of a
// shared test API may log rows with the same source, so the site filters.
func newerThan(t *testing.T, list []logRow, since time.Time) []logRow {
	var out []logRow
	for _, r := range list {
		if r.Site != e2eSite() {
			continue
		}
		at, err := time.Parse(time.RFC3339Nano, r.CreatedAt)
		if err != nil {
			t.Fatalf("created_at %q", r.CreatedAt)
		}
		if at.After(since) {
			out = append(out, r)
		}
	}
	return out
}

// waitRows polls request_log until n rows newer than since are there.
func waitRows(t *testing.T, since time.Time, n int) []logRow {
	var fresh []logRow
	for deadline := time.Now().Add(flushWait); time.Now().Before(deadline); time.Sleep(time.Second) {
		if fresh = newerThan(t, rows(t, 200), since); len(fresh) >= n {
			break
		}
	}
	return fresh
}

func TestE2ECacheHitAndRequestLog(t *testing.T) {
	setSite(t, "enforce", map[string]string{"tor": "block", "vpn": "flag"})
	g := guard(t, edge.Config{SiteID: e2eSite()})
	warm(t)
	ua := uniqueUA(e2eChrome)
	since := time.Now()

	first := g.Check(context.Background(), request(e2eResidential, "", ua), e2eResidential)
	if first.Status != "ok" || first.Cached {
		t.Fatalf("first: %+v", first)
	}
	second := g.Check(context.Background(), request(e2eResidential, "", ua), e2eResidential)
	if second.Status != "ok" || !second.Cached || second.Class != first.Class {
		t.Fatalf("second: %+v", second)
	}
	// A marker check after the cached one: the log is written in order, so
	// once the marker is there a call made by the cached check would be too.
	marker := g.Check(context.Background(), request(e2eVPN, "", uniqueUA(e2eChrome)), e2eVPN)
	if marker.Status != "ok" || marker.Class != "vpn" {
		t.Fatalf("marker: %+v", marker)
	}

	fresh := waitRows(t, since, 2)
	if len(fresh) != 2 {
		t.Fatalf("want the first check and the marker in request_log after %s, got %+v (latest %+v)", since.UTC().Format(time.RFC3339Nano), fresh, rows(t, 4))
	}
	seen := map[string]string{}
	for _, r := range fresh {
		if r.Site != e2eSite() || r.Source != e2eSource || r.Endpoint != "/v1/edge/check" {
			t.Fatalf("row %+v", r)
		}
		seen[r.TrafficClass] = r.Action
	}
	if seen["vpn"] != "flag" || seen[first.Class] == "" {
		t.Fatalf("rows %+v", fresh)
	}
	t.Logf("request_log: %+v", fresh)

	// sites.client_version is this package's version (the upsert prints it).
	row := setSite(t, "enforce", map[string]string{"tor": "block"})
	if row.ClientVersion != edge.Version {
		t.Fatalf("client_version %q", row.ClientVersion)
	}
}

func TestE2ENoSiteConfig(t *testing.T) {
	g := guard(t, edge.Config{Mode: "enforce", BlockClasses: []string{"tor"}})
	if d := g.CheckVisitor(context.Background(), edge.Visitor{IP: e2eTor, UserAgent: uniqueUA(e2eChrome), Method: "GET", Path: "/"}); !d.Blocked() || d.PolicySource != "config" {
		t.Fatalf("tor: %+v", d)
	}
	if d := g.CheckVisitor(context.Background(), edge.Visitor{IP: e2eResidential, UserAgent: uniqueUA(e2eChrome), Method: "GET", Path: "/"}); d.Blocked() || d.Status != "ok" {
		t.Fatalf("residential: %+v", d)
	}

	g = guard(t, edge.Config{BlockClasses: []string{"tor"}})
	if d := g.CheckVisitor(context.Background(), edge.Visitor{IP: e2eTor, UserAgent: uniqueUA(e2eChrome), Method: "GET", Path: "/"}); d.Blocked() || d.Outcome != "would_block" {
		t.Fatalf("monitor: %+v", d)
	}

	// The network class counts: a headless browser on a VPN is blocked with vpn listed.
	g = guard(t, edge.Config{Mode: "enforce", BlockClasses: []string{"vpn"}})
	d := g.CheckVisitor(context.Background(), edge.Visitor{IP: e2eVPN, UserAgent: uniqueUA(e2eHeadless), Method: "GET", Path: "/"})
	if !d.Blocked() || d.Verdict == nil || d.Verdict.Network == nil || d.Verdict.Network.NetworkClass != "vpn" {
		t.Fatalf("headless on vpn: %+v", d)
	}
	t.Logf("headless on vpn: class=%s", d.Class)
}

func TestE2ESpoofedForwardedFor(t *testing.T) {
	setSite(t, "enforce", map[string]string{"tor": "block"})
	g := guard(t, edge.Config{SiteID: e2eSite(), TrustedProxies: []string{"private"}})

	// An internet peer claiming to forward for a Tor exit: its own address counts.
	r := request(e2eResidential, e2eTor, uniqueUA(e2eChrome))
	w := httptest.NewRecorder()
	d, next := g.Handle(w, r)
	if !next || d.IP != e2eResidential || d.Blocked() {
		t.Fatalf("spoofed: %+v", d)
	}
	// The same header from a trusted proxy is believed.
	r = request("127.0.0.1", e2eTor, uniqueUA(e2eChrome))
	w = httptest.NewRecorder()
	d, next = g.Handle(w, r)
	if next || d.IP != e2eTor || w.Code != 403 {
		t.Fatalf("trusted: %+v", d)
	}
}

func TestE2EFailOpenDeadAPI(t *testing.T) {
	g := guard(t, edge.Config{APIURL: "http://127.0.0.1:3999", Mode: "enforce", BlockClasses: []string{"tor"}})
	start := time.Now()
	d := g.CheckVisitor(context.Background(), edge.Visitor{IP: e2eTor, UserAgent: e2eChrome, Method: "GET", Path: "/"})
	if d.Status != "error" || d.Blocked() || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("%+v in %s", d, time.Since(start))
	}
	start = time.Now()
	d = g.CheckVisitor(context.Background(), edge.Visitor{IP: e2eTor, UserAgent: e2eChrome, Method: "GET", Path: "/"})
	if d.Status != "backoff" || time.Since(start) > 50*time.Millisecond {
		t.Fatalf("%+v in %s", d, time.Since(start))
	}
	if st := g.State(); st.BackoffUntil.IsZero() || st.LastStatus != "error" {
		t.Fatalf("%+v", st)
	}
}

func TestE2EFailOpenSlowAPI(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(5 * time.Second):
		case <-r.Context().Done():
		}
	}))
	defer slow.Close()
	g := guard(t, edge.Config{APIURL: slow.URL, Mode: "enforce", BlockClasses: []string{"tor"}})
	start := time.Now()
	d := g.CheckVisitor(context.Background(), edge.Visitor{IP: e2eTor, UserAgent: e2eChrome, Method: "GET", Path: "/"})
	took := time.Since(start)
	if d.Status != "timeout" || d.Blocked() || took < 1400*time.Millisecond || took > 2*time.Second {
		t.Fatalf("%+v in %s", d, took)
	}
	time.Sleep(200 * time.Millisecond)
	if d := g.CheckVisitor(context.Background(), edge.Visitor{IP: e2eTor, UserAgent: e2eChrome, Method: "GET", Path: "/"}); d.Status != "backoff" {
		t.Fatalf("%+v", d)
	}
}
