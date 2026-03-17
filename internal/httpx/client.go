package httpx

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Options struct {
	Timeout     time.Duration
	Delay       time.Duration
	Proxy       string
	InsecureTLS bool
	Headers     http.Header
	UserAgent   string
}

type Client struct {
	httpClient *http.Client
	delay      time.Duration
	headers    http.Header
	ua         string
	mu         sync.Mutex
	rng        *rand.Rand
}

var randomUAs = []string{
	"Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
}

func New(opts Options) (*Client, error) {
	tr := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: opts.InsecureTLS},
		DialContext:         (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		IdleConnTimeout:     90 * time.Second,
	}
	if opts.Proxy != "" {
		p, err := url.Parse(opts.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy: %w", err)
		}
		tr.Proxy = http.ProxyURL(p)
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	headers := make(http.Header)
	for k, v := range opts.Headers {
		vv := make([]string, len(v))
		copy(vv, v)
		headers[k] = vv
	}
	return &Client{
		httpClient: &http.Client{Transport: tr, Timeout: timeout},
		delay:      opts.Delay,
		headers:    headers,
		ua:         opts.UserAgent,
		rng:        rand.New(rand.NewSource(time.Now().UnixNano())),
	}, nil
}

func (c *Client) newRequest(ctx context.Context, method, target string, bodyReader *strings.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, bodyReader)
	if err != nil {
		return nil, err
	}
	for k, v := range c.headers {
		vv := make([]string, len(v))
		copy(vv, v)
		req.Header[k] = vv
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", c.pickUA())
	}
	return req, nil
}

func (c *Client) pickUA() string {
	if c.ua == "" || strings.EqualFold(c.ua, "random") {
		c.mu.Lock()
		defer c.mu.Unlock()
		return randomUAs[c.rng.Intn(len(randomUAs))]
	}
	if strings.EqualFold(c.ua, "default") {
		return randomUAs[0]
	}
	return c.ua
}

func (c *Client) Do(ctx context.Context, method, target string, body string, contentType string) (*http.Response, error) {
	if c.delay > 0 {
		time.Sleep(c.delay)
	}
	rdr := strings.NewReader(body)
	req, err := c.newRequest(ctx, method, target, rdr)
	if err != nil {
		return nil, err
	}
	if body != "" && contentType != "" && req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", contentType)
	}
	return c.httpClient.Do(req)
}
