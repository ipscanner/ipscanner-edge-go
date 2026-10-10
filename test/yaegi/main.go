// Command yaegi runs the package under the Yaegi interpreter, the way
// Traefik loads plugins. Without IPSCANNER_API_URL it starts a stub API;
// with it (and IPSCANNER_API_KEY) it calls the real one.
//
//	sh test/yaegi/run.sh
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"

	edge "github.com/ipscanner/ipscanner-edge-go"
)

const (
	torIP         = "185.220.101.1"
	residentialIP = "84.128.0.1"
	stubSite      = "site_yaegistub0000000000"
	browserUA     = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
)

func stub() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer pk_test_stub" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/v1/sites/"+stubSite+"/policy" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"site":"`+stubSite+`","mode":"enforce","policy":{"tor":"block","vpn":"flag"},"version":3}`)
			return
		}
		if r.URL.Path != "/v1/edge/check" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		class, network := "human", "residential_clean"
		if body["ip"] == torIP {
			class, network = "tor", "tor"
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"class":%q,"agent":{"class":"human","confidence":0.9,"action":"allow","signals":{}},"network":{"networkClass":%q,"anonymized":%t,"riskScore":10,"country":"DE"},"site":null}`,
			class, network, class == "tor")
	}))
}

var failed bool

func expect(name string, ok bool, detail string) {
	state := "ok  "
	if !ok {
		state = "FAIL"
		failed = true
	}
	fmt.Printf("%s %s %s\n", state, name, detail)
}

func main() {
	apiURL := os.Getenv("IPSCANNER_API_URL")
	key := strings.TrimSpace(os.Getenv("IPSCANNER_API_KEY"))
	// A site whose policy is enforce with tor: block.
	site := os.Getenv("IPSCANNER_SITE_ID")
	if apiURL == "" {
		srv := stub()
		defer srv.Close()
		apiURL, key, site = srv.URL, "pk_test_stub", stubSite
	}

	g, err := edge.New(edge.Config{
		APIKey:         key,
		APIURL:         apiURL,
		Mode:           "enforce",
		BlockClasses:   []string{"malicious_automation", "tor"},
		TrustedProxies: []string{"private"},
		Source:         "forward_auth",
		Client:         "forward-auth",
		Version:        edge.Version,
		Debug:          true,
	})
	if err != nil {
		fmt.Println("FAIL new:", err)
		os.Exit(1)
	}

	// Trusted proxy on loopback forwards a Tor visitor: blocked.
	r := httptest.NewRequest("GET", "http://example.test/", nil)
	r.RemoteAddr = "127.0.0.1:5000"
	r.Header.Set("X-Forwarded-For", torIP)
	r.Header.Set("User-Agent", browserUA)
	r.Header.Set("X-IPScanner-Class", "human")
	w := httptest.NewRecorder()
	d, next := g.Handle(w, r)
	expect("tor blocked", !next && w.Code == 403 && d.Class == "tor", fmt.Sprintf("status=%s class=%s outcome=%s code=%d", d.Status, d.Class, d.Outcome, w.Code))

	// Same visitor again: served from the cache.
	d = g.Check(context.Background(), r, torIP)
	expect("cache hit", d.Cached && d.Blocked(), fmt.Sprintf("cached=%t", d.Cached))

	// Residential visitor passes with headers for the upstream.
	r = httptest.NewRequest("GET", "http://example.test/page", nil)
	r.RemoteAddr = residentialIP + ":4000"
	r.Header.Set("User-Agent", browserUA)
	w = httptest.NewRecorder()
	d, next = g.Handle(w, r)
	expect("residential allowed", next && d.Status == "ok" && r.Header.Get("X-IPScanner-Action") == "allow",
		fmt.Sprintf("status=%s class=%s upstream=%s debug=%s", d.Status, d.Class, r.Header.Get("X-IPScanner-Class"), w.Header().Get("X-IPScanner-Status")))

	// Spoofed X-Forwarded-For from an untrusted peer is ignored.
	r = httptest.NewRequest("GET", "http://example.test/", nil)
	r.RemoteAddr = residentialIP + ":4000"
	r.Header.Set("X-Forwarded-For", torIP)
	expect("spoof ignored", g.ClientIP(r) == residentialIP, g.ClientIP(r))

	// Static assets are skipped.
	r = httptest.NewRequest("GET", "http://example.test/app.css", nil)
	r.RemoteAddr = torIP + ":4000"
	d = g.Check(context.Background(), r, torIP)
	expect("skip path", d.Status == "skipped", d.Status)

	if site != "" {
		sg, err := edge.New(edge.Config{APIKey: key, APIURL: apiURL, SiteID: site, Source: "forward_auth", Client: "forward-auth", Version: edge.Version})
		if err != nil {
			fmt.Println("FAIL new site guard:", err)
			os.Exit(1)
		}
		r = httptest.NewRequest("GET", "http://example.test/", nil)
		r.Header.Set("User-Agent", browserUA)
		d = sg.Check(context.Background(), r, torIP)
		expect("site policy blocks tor", d.Blocked() && d.Mode == "enforce" && d.PolicySource == "fetch",
			fmt.Sprintf("status=%s class=%s outcome=%s policy=%s v%d", d.Status, d.Class, d.Outcome, d.PolicySource, d.PolicyVersion))
		d = sg.Check(context.Background(), r, residentialIP)
		expect("site policy allows residential", d.Status == "ok" && !d.Blocked() && d.PolicySource == "cache",
			fmt.Sprintf("status=%s class=%s policy=%s", d.Status, d.Class, d.PolicySource))
	}

	if failed {
		os.Exit(1)
	}
	fmt.Println("yaegi: all checks passed,", g.UserAgent())
}
