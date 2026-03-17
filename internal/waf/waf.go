package waf

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/rohsec/xspulse/internal/httpx"
	"github.com/rohsec/xspulse/internal/model"
)

type signature struct {
	Name   string
	Header *regexp.Regexp
	Body   *regexp.Regexp
	Server *regexp.Regexp
}

var signatures = []signature{
	{Name: "Cloudflare", Header: regexp.MustCompile(`(?i)cf-ray|cf-cache-status`), Body: regexp.MustCompile(`(?i)cloudflare`)},
	{Name: "Akamai", Header: regexp.MustCompile(`(?i)akamai|akamaighost`), Server: regexp.MustCompile(`(?i)akamaighost`)},
	{Name: "Imperva", Header: regexp.MustCompile(`(?i)incapsula|x-iinfo|visid_incap`), Body: regexp.MustCompile(`(?i)imperva|incapsula`)},
	{Name: "Sucuri", Header: regexp.MustCompile(`(?i)x-sucuri|sucuri`), Body: regexp.MustCompile(`(?i)access denied - sucuri website firewall`)},
	{Name: "AWS WAF", Header: regexp.MustCompile(`(?i)x-amzn-requestid|x-amz-cf-id`), Body: regexp.MustCompile(`(?i)request blocked`)},
	{Name: "F5 ASM", Header: regexp.MustCompile(`(?i)x-waf-event|bigip|f5`), Body: regexp.MustCompile(`(?i)the requested url was rejected`)},
}

func headersToString(h http.Header) string {
	var b strings.Builder
	for k, values := range h {
		for _, v := range values {
			b.WriteString(fmt.Sprintf("%s: %s\n", k, v))
		}
	}
	return b.String()
}

func Detect(ctx context.Context, c *httpx.Client, target string) (model.WAFResult, error) {
	probeURL := target
	if strings.Contains(target, "?") {
		probeURL += "&xspulse=%3Csvg%2Fonload%3Dconfirm()%3E"
	} else {
		probeURL += "?xspulse=%3Csvg%2Fonload%3Dconfirm()%3E"
	}
	resp, err := c.Do(ctx, "GET", probeURL, "", "")
	if err != nil {
		return model.WAFResult{}, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	body := string(raw)
	headerStr := headersToString(resp.Header)
	server := resp.Header.Get("Server")

	best := model.WAFResult{URL: target, Status: resp.StatusCode}
	for _, sig := range signatures {
		score := 0.0
		evidence := []string{}
		if sig.Header != nil && sig.Header.MatchString(headerStr) {
			score += 1.0
			evidence = append(evidence, "header")
		}
		if sig.Body != nil && sig.Body.MatchString(body) {
			score += 1.0
			evidence = append(evidence, "body")
		}
		if sig.Server != nil && sig.Server.MatchString(server) {
			score += 0.5
			evidence = append(evidence, "server")
		}
		if resp.StatusCode >= 400 {
			score += 0.25
		}
		if score > best.Score {
			best.Detected = score >= 1.0
			best.Name = sig.Name
			best.Score = score
			best.Evidence = strings.Join(evidence, ",")
			best.Signature = sig.Name
		}
	}
	return best, nil
}
