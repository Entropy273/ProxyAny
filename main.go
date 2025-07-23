package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	sizeLimit int64 = 1024 * 1024 * 1024 * 999 // 999GB
	chunkSize       = getChunkSize()

	allowedDomainsMutex sync.RWMutex
	allowedDomains      = []string{
		"github.com",
		"raw.githubusercontent.com",
		"gist.githubusercontent.com",
		"docker.io",
		"registry-1.docker.io",
		"auth.docker.io",
		"huggingface.co",
		"cdn-lfs.huggingface.co",
		"huggingface.co",
		"hf-mirror.com",
		"modelscope.cn",
		"gitlab.com",
		"gitlab.io",
		"bitbucket.org",
		"sourceforge.net",
		"npmjs.com",
		"registry.npmjs.org",
		"pypi.org",
		"files.pythonhosted.org",
	}

	httpClient *http.Client
	clientOnce sync.Once
)

func getChunkSize() int {
	if sizeStr := os.Getenv("PROXY_CHUNK_SIZE"); sizeStr != "" {
		if size, err := strconv.Atoi(sizeStr); err == nil && size > 0 {
			return size
		}
	}
	return 1024 * 1024
}

func main() {
	initHTTPClient()

	server := &http.Server{
		Addr:         "0.0.0.0:10230",
		Handler:      http.HandlerFunc(indexOrProxy),
		ReadTimeout:  300 * time.Second,
		WriteTimeout: 300 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Println("listen on", server.Addr)
	log.Fatal(server.ListenAndServe())
}

func initHTTPClient() {
	clientOnce.Do(func() {
		httpClient = &http.Client{
			Transport: &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DisableCompression:    true,
				ForceAttemptHTTP2:     true,
				DisableKeepAlives:     false,
				MaxIdleConnsPerHost:   100,
				MaxIdleConns:          1000,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				DialContext: (&net.Dialer{
					Timeout:   30 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Timeout: 300 * time.Second,
		}
	})
}

func indexOrProxy(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		html := `<!DOCTYPE html>
<html>
<head>
    <title>i</title>
    <meta charset="utf-8">
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .domain { background: #f0f0f0; padding: 5px 10px; margin: 5px; border-radius: 3px; display: inline-block; }
        .example { background: #e8f4fd; padding: 10px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>iii</h1>
</body>
</html>`
		io.WriteString(w, html)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/v2/") {
		handleDockerRegistry(w, r)
		return
	}

	if r.URL.Path == "/token" {
		handleDockerAuth(w, r)
		return
	}

	u := strings.TrimPrefix(r.URL.Path, "/")
	handleURL(w, r, u)
}

func isAllowedDomain(url string) bool {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")

	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}

	allowedDomainsMutex.RLock()
	defer allowedDomainsMutex.RUnlock()

	for _, domain := range allowedDomains {
		if url == domain || strings.HasSuffix(url, "."+domain) {
			return true
		}
	}

	return false
}

func extractDomainFromURL(url string) string {
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")

	if idx := strings.Index(url, "/"); idx != -1 {
		url = url[:idx]
	}

	if idx := strings.Index(url, ":"); idx != -1 {
		url = url[:idx]
	}

	return url
}

func handleURL(w http.ResponseWriter, r *http.Request, u string) {
	if !strings.HasPrefix(u, "http") {
		u = "https://" + u
	}

	if idx := strings.Index(u[4:], "://"); idx == -1 {
		u = strings.Replace(u, "s:/", "s://", 1)
	}

	if !isAllowedDomain(u) {
		http.Error(w, "Domain not allowed", http.StatusForbidden)
		return
	}

	proxy(w, r, u)
}

var realmRe = regexp.MustCompile(`(?i)(realm)="[^"]*"`)

func rewriteWWWAuthenticate(orig, newRealm string) string {
	if orig == "" {
		return orig
	}
	if !realmRe.MatchString(orig) {
		if !strings.HasPrefix(strings.ToLower(orig), "bearer") {
			orig = "Bearer " + orig
		}
		return orig + fmt.Sprintf(`,realm="%s"`, newRealm)
	}
	return realmRe.ReplaceAllString(orig, fmt.Sprintf(`$1="%s"`, newRealm))
}

func proxy(w http.ResponseWriter, r *http.Request, base string) {
	target := base + strings.TrimPrefix(r.URL.String(), r.URL.Path)
	if strings.HasPrefix(target, "https:/") && !strings.HasPrefix(target, "https://") {
		target = "https://" + target[7:]
	}

	req, err := http.NewRequest(r.Method, target, r.Body)
	if err != nil {
		http.Error(w, "server error "+err.Error(), 500)
		return
	}

	for k, vv := range r.Header {
		if strings.ToLower(k) == "host" {
			continue
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		http.Error(w, "server error "+err.Error(), 500)
		return
	}
	defer resp.Body.Close()

	if resp.ContentLength > sizeLimit && resp.ContentLength > 0 {
		http.Redirect(w, r, target, http.StatusFound)
		return
	}

	if loc := resp.Header.Get("Location"); loc != "" && (resp.StatusCode/100 == 3) {
		domain := extractDomainFromURL(loc)
		if domain != "" && !slices.Contains(allowedDomains, domain) {
			log.Println("new allowed domain:", domain)
			allowedDomainsMutex.Lock()
			allowedDomains = append(allowedDomains, domain)
			allowedDomainsMutex.Unlock()
		}
		http.Redirect(w, r, "/"+loc, http.StatusFound)
		return
	}

	copyHeaders(w.Header(), resp.Header)
	w.Header().Del("Transfer-Encoding")
	w.Header().Del("Connection")
	w.WriteHeader(resp.StatusCode)

	buf := make([]byte, chunkSize)
	_, err = io.CopyBuffer(w, resp.Body, buf)
	if err != nil {
		log.Println("copy error:", err)
	}
}

func handleDockerRegistry(w http.ResponseWriter, r *http.Request) {
	target := "https://registry-1.docker.io" + r.URL.Path
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}

	req, err := http.NewRequest(r.Method, target, r.Body)
	if err != nil {
		http.Error(w, "server error "+err.Error(), 500)
		return
	}

	req.Header.Set("Host", "registry-1.docker.io")

	for k, vv := range r.Header {
		if strings.ToLower(k) == "host" {
			continue
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	// 使用全局优化的HTTP客户端
	resp, err := httpClient.Do(req)
	if err != nil {
		http.Error(w, "server error "+err.Error(), 500)
		return
	}
	defer resp.Body.Close()

	if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode/100 == 3 {
		domain := extractDomainFromURL(loc)
		if domain != "" && !slices.Contains(allowedDomains, domain) {
			log.Println("new allowed domain:", domain)
			allowedDomainsMutex.Lock()
			allowedDomains = append(allowedDomains, domain)
			allowedDomainsMutex.Unlock()
		}
		http.Redirect(w, r, "/"+loc, http.StatusFound)
		return
	}

	copyHeaders(w.Header(), resp.Header)

	if resp.StatusCode == 401 {
		orig := resp.Header.Get("WWW-Authenticate")
		newVal := rewriteWWWAuthenticate(orig, "https://mirr.top/token")
		w.Header().Del("WWW-Authenticate")
		w.Header().Set("WWW-Authenticate", newVal)
	}

	w.Header().Del("Transfer-Encoding")
	w.Header().Del("Connection")

	w.WriteHeader(resp.StatusCode)

	buf := make([]byte, chunkSize)
	_, err = io.CopyBuffer(w, resp.Body, buf)
	if err != nil {
		log.Println("copy error:", err)
	}
}

func handleDockerAuth(w http.ResponseWriter, r *http.Request) {
	target := "https://auth.docker.io/token"
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}

	req, err := http.NewRequest(r.Method, target, r.Body)
	if err != nil {
		http.Error(w, "server error "+err.Error(), 500)
		return
	}

	req.Header.Set("Host", "auth.docker.io")

	for k, vv := range r.Header {
		if strings.ToLower(k) == "host" {
			continue
		}
		for _, v := range vv {
			req.Header.Add(k, v)
		}
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		http.Error(w, "server error "+err.Error(), 500)
		return
	}
	defer resp.Body.Close()

	if loc := resp.Header.Get("Location"); loc != "" && resp.StatusCode/100 == 3 {
		domain := extractDomainFromURL(loc)
		if domain != "" && !slices.Contains(allowedDomains, domain) {
			log.Println("new allowed domain:", domain)
			allowedDomainsMutex.Lock()
			allowedDomains = append(allowedDomains, domain)
			allowedDomainsMutex.Unlock()
		}
		http.Redirect(w, r, "/"+loc, http.StatusFound)
		return
	}

	copyHeaders(w.Header(), resp.Header)
	w.Header().Del("Transfer-Encoding")
	w.Header().Del("Connection")
	w.WriteHeader(resp.StatusCode)

	buf := make([]byte, chunkSize)
	_, err = io.CopyBuffer(w, resp.Body, buf)
	if err != nil {
		log.Println("copy error:", err)
	}
}

func copyHeaders(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}
