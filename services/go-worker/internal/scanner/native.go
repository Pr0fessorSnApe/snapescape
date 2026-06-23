package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// NativeScanner — all operations in Go, no external tool shell-out.
type NativeScanner struct {
	client *http.Client
}

func NewNativeScanner() *NativeScanner {
	return &NativeScanner{
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (s *NativeScanner) ProbeURL(ctx context.Context, url string) (map[string]interface{}, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SNAPESCAPE/1.0")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	headers := make(map[string]string)
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, ", ")
	}
	return map[string]interface{}{
		"url":            url,
		"status":         resp.StatusCode,
		"headers":        headers,
		"content_length": len(body),
		"title":          extractTitle(string(body)),
	}, nil
}

func (s *NativeScanner) PortScan(ctx context.Context, host string, ports []int, concurrency int) []int {
	var mu sync.Mutex
	var open []int
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for _, port := range ports {
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			addr := fmt.Sprintf("%s:%d", host, p)
			d := net.Dialer{Timeout: 2 * time.Second}
			conn, err := d.DialContext(ctx, "tcp", addr)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}(port)
	}
	wg.Wait()
	return open
}

func (s *NativeScanner) DNSResolve(ctx context.Context, host string) ([]string, error) {
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	result := make([]string, len(ips))
	for i, ip := range ips {
		result[i] = ip.String()
	}
	return result, nil
}

func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title>")
	end := strings.Index(lower, "</title>")
	if start >= 0 && end > start {
		return strings.TrimSpace(body[start+7 : end])
	}
	return ""
}
